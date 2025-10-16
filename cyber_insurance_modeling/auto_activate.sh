#!/bin/zsh
# ===============================
# 自动检测并激活 Python 虚拟环境
# ===============================

PROJECT_DIR="$HOME/cyber-security-score/cyber_insurance_modeling"
VENV_DIR="$PROJECT_DIR/venv"

echo "🔍 检查 Python 虚拟环境状态..."

# 如果虚拟环境不存在，则创建
if [ ! -d "$VENV_DIR" ]; then
  echo "⚙️ 未检测到虚拟环境，正在创建..."
  cd "$PROJECT_DIR" || exit
  python3 -m venv venv
  echo "✅ 虚拟环境已创建"
fi

# 检查是否已激活虚拟环境
if [[ -z "$VIRTUAL_ENV" ]]; then
  echo "🚀 正在激活虚拟环境..."
  source "$VENV_DIR/bin/activate"
  echo "✅ 虚拟环境已激活：$VIRTUAL_ENV"
else
  echo "✅ 虚拟环境已处于激活状态：$VIRTUAL_ENV"
fi

# 验证 python 路径
PYTHON_PATH=$(which python 2>/dev/null)
if [[ -n "$PYTHON_PATH" ]]; then
  echo "🐍 当前 Python 路径：$PYTHON_PATH"
  python --version
else
  echo "❌ 未找到 python，请检查虚拟环境。"
fi

# 自动切换到项目目录
cd "$PROJECT_DIR" || exit
echo "📂 当前目录：$(pwd)"
