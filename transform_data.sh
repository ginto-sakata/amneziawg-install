#!/bin/bash
# Simple transform_data.sh for Linux

INPUT_FILE="./static_website/data.json"
OUTPUT_FILE="./static_website/data.json.transformed"

# Make a backup of the original data
cp "$INPUT_FILE" "$OUTPUT_FILE"

# Perform simple category-based transformations one by one
# Each command is separated for reliability

# 1. Ensure YouTube is in the video category
if jq -e '.categories.youtube' "$OUTPUT_FILE" > /dev/null; then
  # If YouTube category exists, move its services to video category
  jq '.categories.video.services += .categories.youtube.services | del(.categories.youtube)' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
  mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
fi

# 2. Combine Discord services into messengers
if jq -e '.categories.discord' "$OUTPUT_FILE" > /dev/null; then
  # If Discord category exists, move its services to messengers category
  jq 'if .categories.messengers then . else .categories.messengers = {"services": {}} end | .categories.messengers.services += .categories.discord.services | del(.categories.discord)' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
  mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
fi

# 3. Process JetBrains services
if jq -e '.categories.jetbrains' "$OUTPUT_FILE" > /dev/null; then
  # If JetBrains category exists, move to tools
  jq 'if .categories.tools then . else .categories.tools = {"services": {}} end | .categories.tools.services += .categories.jetbrains.services | del(.categories.jetbrains)' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
  mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
fi

# 4. Create entertainment category with music and games
jq 'if .categories.entertainment then . else .categories.entertainment = {"services": {}} end | 
    if .categories.music then .categories.entertainment.services += .categories.music.services | del(.categories.music) else . end |
    if .categories.games then .categories.entertainment.services += .categories.games.services | del(.categories.games) else . end' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

# 5. Create AI category
jq 'if .categories.ai then . else .categories.ai = {"services": {}} end' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

# 6. Move ChatGPT and Claude to AI category
jq 'if .categories.tools and .categories.tools.services["ChatGPT"] then 
      .categories.ai.services["ChatGPT"] = .categories.tools.services["ChatGPT"] | 
      del(.categories.tools.services["ChatGPT"]) 
    else . end' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

jq 'if .categories.tools and .categories.tools.services["Claude"] then 
      .categories.ai.services["Claude"] = .categories.tools.services["Claude"] | 
      del(.categories.tools.services["Claude"]) 
    else . end' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

echo "Data transformation complete. Output saved to $OUTPUT_FILE"