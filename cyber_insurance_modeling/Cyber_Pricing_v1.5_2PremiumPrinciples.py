import numpy as np
from scipy import stats
from scipy.optimize import fsolve
from dataclasses import dataclass
from typing import Tuple, Dict, Literal
import pandas as pd
import time
import os

# Try to import parallel processing libraries
try:
    from concurrent.futures import ProcessPoolExecutor, as_completed

    PARALLEL_AVAILABLE = True
except ImportError:
    PARALLEL_AVAILABLE = False
    print("Warning: Parallel processing not available. Will use sequential processing.")

# Define premium principle type
PremiumPrinciple = Literal["standard_deviation", "equivalent_utility"]


@dataclass
class ScenarioN5Params:
    """Scenario N5: Log-normal infection and recovery (Section 4.1.3)"""

    # Network
    adjacency_matrix: np.ndarray

    # Log-normal parameters from Eq. (4.4)
    mu1: float = 1.1094  # infection from neighbors
    sigma1: float = 1.0
    mu2: float = 0.1931  # external infection
    sigma2: float = 1.0
    mu_v: float = -0.5  # recovery time
    sigma_v: float = 1.0

    # Loss parameters (Section 4, page 19-20)
    omega_v: float = 10.0  # initial wealth
    a: float = 2.0  # Beta shape
    b: float = 4.0  # Beta shape
    c: float = 0.001  # infection cost rate
    c1: float = 0.1e-6  # fixed recovery cost
    c2: float = 0.5e-4  # time-based recovery cost

    # Simulation
    T_max: float = 365.0
    num_simulations: int = 10

    # ========== PREMIUM PRINCIPLE SELECTION ==========
    # Choose: "standard_deviation" (Eq. 4.2) or "equivalent_utility" (Eq. 4.3)
    # premium_principle: PremiumPrinciple = "standard_deviation"
    premium_principle: PremiumPrinciple = "equivalent_utility"

    # Parameters for standard deviation principle (Eq. 4.2)
    lambda_risk: float = 0.2  # risk loading: H(X) = E[X] + λ√Var(X)

    # Parameters for equivalent utility principle (Eq. 4.3)
    gamma: float = 0.8  # risk aversion: u(ω) = E[u(ω - X + H)]
    # ==================================================

    # Parallel processing
    use_parallel: bool = True  # Enable/disable parallel processing


def get_cpu_count():
    """Get CPU count in a robust way"""
    try:
        return os.cpu_count() or 1
    except:
        return 1


def crra_utility(wealth: float, gamma: float) -> float:
    """
    CRRA (Constant Relative Risk Aversion) utility function

    u(ω) = { (ω^(1-γ))/(1-γ)  if γ ≠ 1
           { log(ω)            if γ = 1
    """
    if gamma == 1.0:
        return np.log(wealth) if wealth > 0 else -np.inf
    else:
        return (wealth ** (1 - gamma)) / (1 - gamma) if wealth > 0 else -np.inf


def solve_equivalent_utility_premium(
    initial_wealth: float, losses: np.ndarray, gamma: float
) -> float:
    """
    Solve for premium H using principle of equivalent utility (Eq. 4.3):
    u(ω) = E[u(ω - X + H)]

    Args:
        initial_wealth: ω_v
        losses: Array of loss samples X
        gamma: Risk aversion parameter

    Returns:
        Premium H
    """
    # Left side: u(ω)
    u_omega = crra_utility(initial_wealth, gamma)

    # Define equation to solve: u(ω) - E[u(ω - X + H)] = 0
    def equation(H):
        # Calculate u(ω - X + H) for each loss sample
        wealth_after = initial_wealth - losses + H

        # Handle cases where wealth becomes non-positive
        utilities = np.array([crra_utility(w, gamma) for w in wealth_after])

        # Expected utility
        expected_utility = np.mean(utilities)

        return u_omega - expected_utility

    # Initial guess: start with expected loss
    H_initial = np.mean(losses)

    try:
        # Solve for H
        H_solution = fsolve(equation, H_initial, full_output=True)
        H = H_solution[0][0]

        # Verify solution is reasonable
        if H < 0 or H > initial_wealth:
            print(
                f"Warning: Premium solution {H:.2f} seems unreasonable, using mean loss"
            )
            H = np.mean(losses)

        return H
    except:
        # If optimization fails, fall back to expected loss
        print("Warning: Equivalent utility optimization failed, using mean loss")
        return np.mean(losses)


class IndependentLogNormalModel:
    """Independent model with log-normal processes (Scenario N5)"""

    def __init__(self, params: ScenarioN5Params):
        self.params = params
        self.N = len(params.adjacency_matrix)
        self.A = params.adjacency_matrix

        # Validate premium principle
        if params.premium_principle not in ["standard_deviation", "equivalent_utility"]:
            raise ValueError(
                f"Invalid premium_principle: '{params.premium_principle}'. "
                f"Must be 'standard_deviation' or 'equivalent_utility'"
            )

    def sample_infection_time(self, num_infected_neighbors: int) -> float:
        """
        Sample time to infection: T_v = min(Y_v1, ..., Y_vD_v, Z_v)
        Independent log-normal distributions
        """
        p = self.params

        # External infection Z_v ~ LogNormal(mu2, sigma2)
        Z_v = stats.lognorm.rvs(s=p.sigma2, scale=np.exp(p.mu2))

        if num_infected_neighbors == 0:
            return Z_v

        # Neighbor infections Y_vj ~ LogNormal(mu1, sigma1) (independent)
        Y_times = stats.lognorm.rvs(
            s=p.sigma1, scale=np.exp(p.mu1), size=num_infected_neighbors
        )

        return min(Z_v, np.min(Y_times))

    def sample_recovery_time(self) -> float:
        """Recovery time R_v ~ LogNormal(mu_v, sigma_v)"""
        p = self.params
        return stats.lognorm.rvs(s=p.sigma_v, scale=np.exp(p.mu_v))

    def calculate_loss(self, recovery_time: float) -> float:
        """
        Calculate loss from infection event (Eq. 4.1)
        η_v(L_v,i) + C_v(R_v,i)
        """
        p = self.params

        # Information loss L_v,i ~ Beta(a, b) * omega_v
        L = stats.beta.rvs(p.a, p.b) * p.omega_v

        # Cost from infection
        eta = p.c * L

        # Cost from recovery
        C = p.c1 * p.omega_v + p.c2 * recovery_time

        return eta + C

    def simulate_one_year(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Algorithm 1: Simulate network for one year
        Returns: (num_infections_per_node, total_loss_per_node)
        """
        t = 0.0
        I = np.zeros(self.N, dtype=int)  # status: 0=secure, 1=infected
        M = np.zeros(self.N, dtype=int)  # count infections
        S = np.zeros(self.N)  # cumulative loss

        infection_start_times = {}  # track when each node was infected

        while t < self.params.T_max:
            events = []

            # Step 4: For each secure node, generate infection time
            for v in range(self.N):
                if I[v] == 0:
                    D_v = int(np.sum(self.A[v, :] * I))  # infected neighbors
                    t_inf = self.sample_infection_time(D_v)
                    events.append((t + t_inf, v, "infection"))

            # For each infected node, generate recovery time
            for v in range(self.N):
                if I[v] == 1:
                    t_rec = self.sample_recovery_time()
                    events.append((t + t_rec, v, "recovery"))

            if not events:
                break

            # Step 5: Determine next event
            events.sort(key=lambda x: x[0])
            t_next, node, event_type = events[0]

            if t_next > self.params.T_max:
                break

            # Step 11: Update time
            t = t_next

            if event_type == "infection":
                # Step 6-7: Infection occurs
                I[node] = 1
                M[node] += 1
                infection_start_times[node] = t
            else:
                # Step 8-9: Recovery occurs
                R_v = t - infection_start_times[node]
                loss = self.calculate_loss(R_v)
                S[node] += loss
                I[node] = 0

        return M, S

    def calculate_premiums_sequential(self) -> Dict:
        """Sequential Monte Carlo simulation"""
        all_infections = []
        all_losses = []

        print(f"\n Running {self.params.num_simulations} simulations sequentially...")
        start_time = time.time()

        for i in range(self.params.num_simulations):
            if (i + 1) % 500 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                remaining = (self.params.num_simulations - i - 1) / rate
                print(
                    f"  Completed {i + 1}/{self.params.num_simulations} "
                    f"({(i+1)/self.params.num_simulations*100:.1f}%) - "
                    f"Est. time remaining: {remaining:.1f}s"
                )

            M, S = self.simulate_one_year()
            all_infections.append(M)
            all_losses.append(S)

        elapsed = time.time() - start_time
        print(f"\n Sequential execution completed in {elapsed:.2f} seconds")
        print(
            f"  Average: {elapsed/self.params.num_simulations*1000:.2f} ms per simulation"
        )

        return self._process_results(all_infections, all_losses)

    def calculate_premiums_parallel(self, n_cores: int = None) -> Dict:
        """
        Parallel Monte Carlo simulation using concurrent.futures

        Args:
            n_cores: Number of cores to use (default: cpu_count() - 1)
        """
        if not PARALLEL_AVAILABLE:
            print("\n⚠ Parallel processing not available. Falling back to sequential.")
            return self.calculate_premiums_sequential()

        # Detect number of CPUs
        total_cores = get_cpu_count()

        if n_cores is None:
            n_cores = max(1, total_cores - 1)  # Use N-1 cores
        else:
            n_cores = min(n_cores, total_cores)

        print(f"\n{'='*70}")
        print(f"PARALLEL PROCESSING SETUP")
        print(f"{'='*70}")
        print(f"Total CPU cores detected:     {total_cores}")
        print(f"Cores to be used:             {n_cores}")
        print(f"Cores left for system:        {total_cores - n_cores}")
        print(f"Total simulations:            {self.params.num_simulations}")
        print(
            f"Simulations per core:         ~{self.params.num_simulations // n_cores}"
        )
        print(f"{'='*70}\n")

        print(
            f"Running {self.params.num_simulations} simulations on {n_cores} cores..."
        )
        start_time = time.time()

        all_infections = []
        all_losses = []

        try:
            # Use ProcessPoolExecutor for CPU-bound tasks
            with ProcessPoolExecutor(max_workers=n_cores) as executor:
                # Submit all simulations
                futures = []
                for i in range(self.params.num_simulations):
                    future = executor.submit(
                        run_single_simulation_wrapper, self.params, i
                    )
                    futures.append(future)

                # Collect results as they complete
                completed = 0
                for future in as_completed(futures):
                    M, S = future.result()
                    all_infections.append(M)
                    all_losses.append(S)

                    completed += 1
                    if completed % 500 == 0 or completed == self.params.num_simulations:
                        elapsed = time.time() - start_time
                        rate = completed / elapsed
                        remaining = (
                            (self.params.num_simulations - completed) / rate
                            if completed < self.params.num_simulations
                            else 0
                        )
                        print(
                            f"  Completed {completed}/{self.params.num_simulations} "
                            f"({completed/self.params.num_simulations*100:.1f}%) - "
                            f"Est. time remaining: {remaining:.1f}s"
                        )

        except Exception as e:
            print(f"\n Parallel execution failed: {e}")
            print("Falling back to sequential processing...")
            return self.calculate_premiums_sequential()

        elapsed = time.time() - start_time
        speedup = (self.params.num_simulations * 0.15) / elapsed  # Rough estimate
        print(f"\n Parallel execution completed in {elapsed:.2f} seconds")
        print(
            f" Average: {elapsed/self.params.num_simulations*1000:.2f} ms per simulation"
        )
        print(f" Estimated speedup: ~{speedup:.1f}x")

        return self._process_results(all_infections, all_losses)

    def _process_results(self, all_infections, all_losses) -> Dict:
        """Process simulation results and calculate premiums"""
        all_infections = np.array(all_infections)
        all_losses = np.array(all_losses)

        # Node-level statistics
        node_mean_infections = np.mean(all_infections, axis=0)
        node_mean_losses = np.mean(all_losses, axis=0)
        node_std_losses = np.std(all_losses, axis=0)

        # Calculate premiums based on chosen principle
        if self.params.premium_principle == "standard_deviation":
            # Eq. 4.2: H(X) = E[X] + λ * √Var(X)
            # print(f"\n{'='*70}")
            # print(f" PREMIUM CALCULATION: Standard Deviation Principle")
            # print(f"{'='*70}")
            # print(f" Formula: H(X) = E[X] + {self.params.lambda_risk} × √Var(X)")

            node_premiums = node_mean_losses + self.params.lambda_risk * node_std_losses

            network_losses = np.sum(all_losses, axis=1)
            network_mean = np.mean(network_losses)
            network_std = np.std(network_losses)
            network_premium = network_mean + self.params.lambda_risk * network_std

        elif self.params.premium_principle == "equivalent_utility":
            # Eq. 4.3: u(ω) = E[u(ω - X + H)]
            print(f"\n{'='*70}")
            print(f" PREMIUM CALCULATION: Equivalent Utility Principle")
            print(f"{'='*70}")
            # print(f" Formula: u(ω) = E[u(ω - X + H)]")
            # print(f" Risk aversion parameter γ = {self.params.gamma}")
            print(f" Solving numerically for each node...")

            node_premiums = np.zeros(self.N)
            for v in range(self.N):
                node_losses = all_losses[:, v]
                node_premiums[v] = solve_equivalent_utility_premium(
                    self.params.omega_v, node_losses, self.params.gamma
                )
                if (v + 1) % 3 == 0 or v == self.N - 1:
                    print(f"  ✓ Nodes 1-{v+1} completed")

            # Network-level premium
            network_losses = np.sum(all_losses, axis=1)
            network_mean = np.mean(network_losses)
            network_std = np.std(network_losses)

            # For network, use total initial wealth
            total_wealth = self.params.omega_v * self.N
            print(f" Computing network premium...")
            network_premium = solve_equivalent_utility_premium(
                total_wealth, network_losses, self.params.gamma
            )
            print(f" Network premium completed")

        else:
            raise ValueError(
                f" Unknown premium principle: {self.params.premium_principle}"
            )

        return {
            "node_premiums": node_premiums,
            "node_mean_losses": node_mean_losses,
            "node_std_losses": node_std_losses,
            "node_mean_infections": node_mean_infections,
            "network_premium": network_premium,
            "network_mean_loss": network_mean,
            "network_std_loss": network_std,
            "all_losses": all_losses,
            "all_infections": all_infections,
            "premium_principle": self.params.premium_principle,
        }

    def calculate_premiums(self, n_cores: int = None) -> Dict:
        """
        Main entry point for premium calculation
        Automatically chooses parallel or sequential based on params.use_parallel

        Args:
            n_cores: Number of cores to use (default: cpu_count() - 1)
        """
        if self.params.use_parallel and PARALLEL_AVAILABLE:
            return self.calculate_premiums_parallel(n_cores)
        else:
            if self.params.use_parallel and not PARALLEL_AVAILABLE:
                print("\n Note: Parallel processing requested but not available.")
            return self.calculate_premiums_sequential()


# Wrapper function for parallel processing (must be at module level)
def run_single_simulation_wrapper(
    params: ScenarioN5Params, seed: int
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Wrapper function to run a single simulation
    Must be at module level for ProcessPoolExecutor to pickle it
    """
    np.random.seed(seed)
    model = IndependentLogNormalModel(params)
    return model.simulate_one_year()


def print_results(results: Dict, params: ScenarioN5Params, A: np.ndarray):
    """Pretty print results"""
    print("\n" + "=" * 70)
    print("Chosen Model: Independent Log-Normal Model")
    print("=" * 70)
    print(f"\nDistribution Parameters:")
    print(
        f"  (μ₁, σ₁, μ₂, σ₂, μᵥ, σᵥ) = "
        f"({params.mu1}, {params.sigma1}, {params.mu2}, "
        f"{params.sigma2}, {params.mu_v}, {params.sigma_v})"
    )

    # Print premium principle
    if params.premium_principle == "standard_deviation":
        print(f"\n Premium Principle: Standard Deviation")
        print(f"  H(X) = E[X] + λ√Var(X) with λ = {params.lambda_risk}")
    else:
        print(f"\n Premium Principle: Equivalent Utility")
        print(f"  u(ω) = E[u(ω - X + H)] with γ = {params.gamma}")

    print("\n" + "=" * 70)
    print("Cyber Insurance Contract")
    print("=" * 70)
    print(f"\nContract Period: {params.T_max} days")
    print(f"Total Insured Asset: ${100 :>10.2f}")
    print(f"Number of Simulations: {params.num_simulations}")

    # Create results table
    df = pd.DataFrame(
        {
            "Node": range(len(results["node_premiums"])),
            "Degree": np.sum(A, axis=1).astype(int),
            "Mean Infections": results["node_mean_infections"].round(3),
            "Mean Loss ($)": results["node_mean_losses"].round(2),
            "Std Loss ($)": results["node_std_losses"].round(2),
            "Premium ($)": results["node_premiums"].round(2),
        }
    )

    # print("\n" + df.to_string(index=False))

    print("\n" + "=" * 70)
    print("Cyber Insurnace Premium")
    print("-" * 70)
    print(f"Total Premium:     ${results['network_premium']:>10.2f}")
    # print(f"Expected Loss:     ${results['network_mean_loss']:>10.2f}")
    # print(f"Loss Std Dev:      ${results['network_std_loss']:>10.2f}")

    # Risk loading calculation for standard deviation
    # if params.premium_principle == "standard_deviation":
    #    risk_load = results['network_premium'] - results['network_mean_loss']
    #    risk_load_pct = risk_load / results['network_mean_loss'] * 100
    #    print(f"Risk Loading:      ${risk_load:>10.2f} ({risk_load_pct:.2f}%)")

    # Compare with Table 3 from paper (Scenario N5)
    # print("\n" + "="*70)
    # print("COMPARISON WITH PAPER (Table 3, Scenario N5)")
    # print("="*70)
    # paper_results = {
    #    'Mean Infections': [82.689, 81.129, 84.832, 75.459, 77.906, 78.958, 78.811, 82.595, 79.121, 77.170],
    #    'Mean Loss': [31.823, 31.277, 32.697, 29.039, 30.005, 30.412, 30.465, 31.811, 30.591, 29.630],
    #    'Network Loss': 307.752
    # }

    # print(f"\nYour results vs Paper:")
    # print(f"  Node 3 Mean Infections: {results['node_mean_infections'][2]:.1f} vs {paper_results['Mean Infections'][2]:.1f}")
    # print(f"  Node 3 Mean Loss:       ${results['node_mean_losses'][2]:.2f} vs ${paper_results['Mean Loss'][2]:.2f}")
    # print(f"  Network Mean Loss:      ${results['network_mean_loss']:.2f} vs ${paper_results['Network Loss']:.2f}")

    # Calculate percentage difference
    # diff_pct = abs(results['network_mean_loss'] - paper_results['Network Loss']) / paper_results['Network Loss'] * 100
    # print(f"  Difference:             {diff_pct:.2f}%")


# Example: Use Figure 1 network
if __name__ == "__main__":
    A = np.array(
        [
            [0, 1, 1, 0, 1, 0, 0, 1, 0, 0],
            [1, 0, 1, 1, 1, 0, 0, 0, 0, 0],
            [1, 1, 0, 0, 1, 1, 1, 1, 1, 1],
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 1, 0, 0, 1, 0, 0, 0, 1],
            [0, 0, 1, 0, 1, 0, 1, 0, 1, 0],
            [0, 0, 1, 0, 0, 1, 0, 0, 1, 0],
            [1, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 1, 0, 0, 1, 1, 0, 0, 0],
            [0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        ]
    )

    # ========== SIMPLE USAGE: JUST CHANGE THIS PARAMETER ==========

    # Option 1: Standard Deviation Principle (Eq. 4.2)
    # PREMIUM_PRINCIPLE = "standard_deviation"  # Change to "equivalent_utility" for Eq. 4.3
    PREMIUM_PRINCIPLE = "equivalent_utility"

    # ===============================================================

    params = ScenarioN5Params(
        adjacency_matrix=A,
        num_simulations=10,
        premium_principle=PREMIUM_PRINCIPLE,  # ← THE KEY PARAMETER
        lambda_risk=0.2,  # For standard deviation
        gamma=0.8,  # For equivalent utility
        use_parallel=True,
    )

    model = IndependentLogNormalModel(params)
    results = model.calculate_premiums()
    print_results(results, params, A)

    print("\n" + "=" * 70)
    print("TO SWITCH PREMIUM PRINCIPLE:")
    print("  Change PREMIUM_PRINCIPLE to:")
    print("    'standard_deviation' ")
    print("    'equivalent_utility' ")
    print("=" * 70)
