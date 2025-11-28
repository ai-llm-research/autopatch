
more_option=""
case "$1" in
  llama)
    model="codellama/CodeLlama-13b-Instruct-hf"
    ;;
  deepseek)
    model="deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"
    ;;
  deepseek-r1)
    model="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"
    more_option="--max-model-len 32000"
    ;;
  *)
    echo "Unknown model keyword: $1"
    ;;
esac

vllm serve "$model" --tensor-parallel-size 1 $more_option --trust-remote-code
