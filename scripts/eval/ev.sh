#!/bin/bash
model="$1"

if [[ "$model" != "gpt-4o" && "$model" != "o3-mini" && "$model" != "deepseek-r1"  ]]; then
  echo "Invalid model: $model"
  echo "Valid options are: gpt-4o, o3-mini, deepseek-r1"
  exit 1
fi

$(dirname -- "$0")/ev1.sh $model
$(dirname -- "$0")/ev2.sh $model
$(dirname -- "$0")/ev3.sh $model
$(dirname -- "$0")/ev4.sh $model
$(dirname -- "$0")/ev5.sh $model