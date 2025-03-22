#!/bin/bash
# transform_data.sh - Script to reorganize categories and services with proper naming

INPUT_FILE="./static_website/data.json"
OUTPUT_FILE="./static_website/data.json.transformed"

# Make sure jq is available
if ! command -v jq &> /dev/null; then
    echo "jq is required for this script. Please install it."
    exit 1
fi

echo "Transforming data from $INPUT_FILE to $OUTPUT_FILE..."

# Create a descriptions database
cat > descriptions.json << EOF
{
  "YouTube": "World's largest video sharing platform",
  "Netflix": "Subscription streaming service for movies and TV shows",
  "Discord": "Voice, video and text chat platform for communities",
  "Telegram": "Cloud-based instant messaging service",
  "WhatsApp": "End-to-end encrypted messaging and calling app",
  "Spotify": "Digital music streaming service",
  "Facebook": "Social networking platform connecting people worldwide",
  "Twitter": "Microblogging and social networking service",
  "Instagram": "Photo and video sharing social networking service",
  "TikTok": "Short-form video hosting service",
  "Reddit": "Social news aggregation and discussion website",
  "LinkedIn": "Professional networking platform",
  "GitHub": "Code hosting platform for version control and collaboration",
  "Amazon": "Global online shopping platform",
  "Google": "Search engine and digital services provider",
  "Microsoft": "Software, hardware and cloud computing company",
  "Apple": "Technology company producing consumer electronics and software",
  "ChatGPT": "AI-powered chatbot by OpenAI",
  "Claude": "AI assistant by Anthropic",
  "Coursera": "Online learning platform with university courses",
  "Udemy": "Online learning and teaching marketplace",
  "Twitch": "Live streaming service for gaming, entertainment and more",
  "Steam": "Digital distribution platform for video games",
  "Epic Games": "Digital video game storefront and game developer",
  "Hulu": "Subscription video on demand service",
  "Disney+": "Subscription video streaming service by Disney",
  "HBO Max": "Streaming platform for HBO content and more",
  "Crunchyroll": "Anime and manga streaming platform",
  "Medium": "Online publishing platform for writers",
  "Notion": "All-in-one workspace for notes, tasks and collaboration",
  "Slack": "Business communication platform",
  "Zoom": "Video conferencing and online chat service",
  "Dropbox": "File hosting service for cloud storage",
  "OneDrive": "Microsoft's file hosting service",
  "Google Drive": "File storage and synchronization service by Google",
  "JetBrains": "Professional software development tools and IDEs",
  "Visual Studio Code": "Source code editor by Microsoft",
  "Adobe": "Software company specializing in creative software",
  "Canva": "Graphic design platform for creating visual content",
  "Figma": "Collaborative interface design tool",
  "Trello": "Web-based list-making application for project management",
  "Asana": "Web and mobile application for project management",
  "Jira": "Issue tracking product for software development",
  "Gmail": "Email service by Google",
  "Outlook": "Personal information manager by Microsoft",
  "Proton Mail": "End-to-end encrypted email service",
  "ProtonVPN": "Secure VPN service by Proton",
  "NordVPN": "Virtual private network service provider",
  "ExpressVPN": "VPN service for anonymous and encrypted internet browsing",
  "Cloudflare": "Web infrastructure and security company",
  "AWS": "Cloud computing platform by Amazon",
  "Azure": "Cloud computing service by Microsoft",
  "Google Cloud": "Cloud computing services by Google",
  "PayPal": "Online payment system for money transfers",
  "Stripe": "Online payment processing platform",
  "Shopify": "E-commerce platform for online stores",
  "eBay": "Online auction and shopping website",
  "Alibaba": "Global wholesale marketplace",
  "Wikipedia": "Free online encyclopedia created through collaboration",
  "Stack Overflow": "Q&A site for programmers",
  "Quora": "Q&A platform where questions are asked and answered",
  "BBC": "British Broadcasting Corporation news service",
  "CNN": "Cable News Network for breaking news",
  "New York Times": "American newspaper with global coverage",
  "The Guardian": "British newspaper with international coverage",
  "ESPN": "Sports news, scores, and commentary",
  "Airbnb": "Online marketplace for lodging and tourism activities",
  "Booking.com": "Online travel agency for lodging reservations",
  "Uber": "Ride-hailing and delivery platform",
  "Lyft": "Ride-sharing company",
  "Yelp": "Business directory and review forum",
  "Tripadvisor": "Travel guidance platform for reviews and bookings",
  "Duolingo": "Language learning platform and educational app",
  "Khan Academy": "Educational organization with free learning resources",
  "EdX": "Provider of massive open online courses",
  "Midjourney": "AI image generation service",
  "DALL-E": "AI system by OpenAI that creates images from text descriptions",
  "Stable Diffusion": "AI art generation model",
  "Hugging Face": "AI community and model platform",
  "Perplexity": "AI-powered search engine",
  "Codecademy": "Interactive platform for learning programming",
  "LeetCode": "Platform for practicing coding skills",
  "HackerRank": "Technical hiring platform for assessing developer skills",
  "Kaggle": "Data science and machine learning community",
  "Arxiv": "Open-access archive for scholarly articles",
  "ResearchGate": "Social networking site for scientists and researchers",
  "Google Scholar": "Search engine for scholarly literature",
  "PornHub": "Adult entertainment website with video content",
  "OnlyFans": "Subscription-based social media service",
  "Roblox": "Online game platform and game creation system",
  "Minecraft": "Sandbox video game",
  "Fortnite": "Online multiplayer battle royale game",
  "League of Legends": "Multiplayer online battle arena game",
  "Dailymotion": "Video sharing platform alternative to YouTube",
  "Vimeo": "Video hosting, sharing, and services platform",
  "SoundCloud": "Online audio distribution platform",
  "Apple Music": "Music and video streaming service by Apple",
  "Deezer": "Music streaming service",
  "Tidal": "Music streaming service with high fidelity sound",
  "Bandcamp": "Music platform for independent artists and labels",
  "IMDb": "Online database of information on films and television",
  "Goodreads": "Social cataloging website for book enthusiasts",
  "Audible": "Online audiobook and podcast service",
  "Webflow": "Visual web design platform",
  "WordPress": "Content management system for websites and blogs",
  "Shopify": "E-commerce platform for online stores and retail point-of-sale systems",
  "Wix": "Cloud-based web development platform",
  "Elementor": "Website builder platform for WordPress",
  "Mailchimp": "Marketing automation platform for email marketing",
  "HubSpot": "Inbound marketing, sales, and CRM software",
  "SendGrid": "Cloud-based email service",
  "DocuSign": "Electronic signature technology",
  "Evernote": "App for note taking and task management",
  "OneNote": "Note-taking program by Microsoft",
  "Google Keep": "Note-taking service by Google",
  "LastPass": "Password manager and digital vault",
  "1Password": "Password manager and digital vault",
  "Bitwarden": "Open-source password management service",
  "Grammarly": "Digital writing assistance tool",
  "Google Translate": "Multilingual neural machine translation service",
  "DeepL": "Neural machine translation service",
  "Zapier": "Automation tool that connects different apps",
  "IFTTT": "Web-based service for creating applets that work across apps",
  "Make": "Automation platform for connecting apps and automating workflows",
  "Airtable": "Spreadsheet-database hybrid with the features of a database",
  "Miro": "Online collaborative whiteboard platform",
  "Confluence": "Team workspace and collaboration tool",
  "Basecamp": "Project management and team communication software",
  "Copilot": "AI-powered code completion tool by GitHub",
  "Elevenlabs": "AI voice generation platform",
  "Copilot": "AI-powered code completion and generation tool",
  "ThePirateBay": "Torrent website for digital content",
  "Torrentz": "BitTorrent meta-search engine",
  "CrackWatch": "Website tracking game crack statuses",
  "FitBit": "Fitness tracking products and services",
  "Garmin": "GPS technology, fitness, and outdoor sports products",
  "Whoop": "Fitness wearable device and subscription service",
  "Strava": "Internet service for tracking physical exercise"
}
EOF

# Start with a copy of the original data
cp "$INPUT_FILE" "$OUTPUT_FILE.tmp"

# Process and format service names
jq --slurpfile descriptions descriptions.json '
  # Create a function to format service names properly
  def formatServiceName(name):
    # Remove duplicated names (e.g. "ClaudeAiClaudeAi" -> "ClaudeAi")
    if (name | length) % 2 == 0 and (name | length) > 4 then
      $half_length = (name | length) / 2;
      $first_half = name[0:$half_length];
      $second_half = name[$half_length:];
      if $first_half == $second_half then $first_half else name end
    else name end | 
    
    # Convert common suffixes
    if endswith("Com") then .[0:-3] 
    elif endswith("Net") then .[0:-3]
    elif endswith("Io") then .[0:-2]
    elif endswith("Ai") then .[0:-2]
    elif endswith("So") then .[0:-2]
    else . end |
    
    # Add proper spacing
    # Add a space before capital letters except the first one
    gsub("(?<=[a-z])(?=[A-Z])"; " ") |
    
    # Preserve common abbreviations
    gsub(" G P T"; "GPT") |
    gsub(" V P N"; "VPN") |
    gsub(" I M D B"; "IMDB") |
    gsub(" H B O"; "HBO") |
    gsub(" A W S"; "AWS") |
    gsub(" I D E"; "IDE") |
    gsub(" A I"; "AI") |
    
    # Capitalize first letter
    if length > 0 then
      (.[0:1] | ascii_upcase) + (.[1:] | .)
    else . end;
  
  # Function to get a description for a service
  def getDescription(name):
    $descriptions[0] as $desc |
    name as $key |
    if $desc[$key] then
      $desc[$key]
    else
      # Try to match by partial name
      ($desc | to_entries[] | select(.key | inside($key) or $key | inside(.key)) | .value) //
      # Try without spaces
      ($desc | to_entries[] | select(.key | gsub(" "; "") | inside($key | gsub(" "; "")) or $key | gsub(" "; "") | inside(.key | gsub(" "; ""))) | .value) //
      # Default description
      ("Access " + name + " online services")
    end
  };
  
  # Process each category and its services
  . as $root |
  $root.categories |= (
    to_entries | map(
      .value.services |= (
        to_entries | map(
          # Format the service name properly
          $formatted_name = (formatServiceName(.key));
          # Replace with properly formatted name and description
          {
            key: $formatted_name,
            value: (.value + {
              # Add description if not already present
              description: (.value.description // getDescription($formatted_name))
            })
          }
        ) | from_entries
      )
    ) | from_entries
  )
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE.tmp2"
mv "$OUTPUT_FILE.tmp2" "$OUTPUT_FILE.tmp"

# 1. Combine all Discord services from different categories
jq '
  # First, capture all Discord-related services across categories
  . as $root |
  reduce ($root.categories | keys[]) as $category (
    [];
    . + (
      $root.categories[$category].services | 
      to_entries | 
      map(select(.key | test("Discord"; "i") or .key == "Discord")) |
      map({key: .key, value: .value, category: $category})
    )
  ) as $discordServices |
  
  # Create a combined Discord CIDR list
  ($discordServices | map(.value.cidrs) | add | unique) as $combinedCidrs |
  
  # Make sure "messengers" category exists
  if $root.categories.messengers then . else 
    .categories.messengers = {"services": {}} 
  end |
  
  # Add the combined Discord service to messengers
  .categories.messengers.services.Discord = {
    "url": "https://discord.com",
    "description": "Voice, video and text chat platform for communities",
    "cidrs": $combinedCidrs
  } |
  
  # Remove Discord services from their original categories
  reduce $discordServices[] as $service (
    .;
    del(.categories[$service.category].services[$service.key])
  )
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE.tmp2"
mv "$OUTPUT_FILE.tmp2" "$OUTPUT_FILE.tmp"

# 2. Combine Jetbrains services
jq '
  # Capture all Jetbrains services
  . as $root |
  reduce ($root.categories | keys[]) as $category (
    [];
    . + (
      $root.categories[$category].services | 
      to_entries | 
      map(select(.key | test("Jetbrains"; "i") or .key == "Jetbrains")) |
      map({key: .key, value: .value, category: $category})
    )
  ) as $jetbrainsServices |
  
  # Create a combined Jetbrains CIDR list
  ($jetbrainsServices | map(.value.cidrs) | add | unique) as $combinedCidrs |
  
  # Make sure "tools" category exists
  if $root.categories.tools then . else 
    .categories.tools = {"services": {}} 
  end |
  
  # Add the combined Jetbrains service to tools
  .categories.tools.services["JetBrains"] = {
    "url": "https://jetbrains.com",
    "description": "Professional development tools and IDEs",
    "cidrs": $combinedCidrs
  } |
  
  # Remove Jetbrains category if it exists
  del(.categories.jetbrains) |
  
  # Remove Jetbrains services from other categories
  reduce $jetbrainsServices[] as $service (
    .;
    del(.categories[$service.category].services[$service.key])
  )
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE.tmp2"
mv "$OUTPUT_FILE.tmp2" "$OUTPUT_FILE.tmp"

# 3. Combine Music and Games categories into "Entertainment"
jq '
  # Create entertainment category if it doesn't exist
  if .categories.entertainment then . else
    .categories.entertainment = {"services": {}}
  end |
  
  # Move all services from music to entertainment
  if .categories.music then
    .categories.entertainment.services += .categories.music.services |
    del(.categories.music)
  else . end |
  
  # Move all services from games to entertainment
  if .categories.games and (.categories.games.services | length < 5) then
    .categories.entertainment.services += .categories.games.services |
    del(.categories.games)
  else . end |
  
  # Move shop services to entertainment if only a few
  if .categories.shop and (.categories.shop.services | length < 3) then
    .categories.entertainment.services += .categories.shop.services |
    del(.categories.shop)
  else . end
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE.tmp2"
mv "$OUTPUT_FILE.tmp2" "$OUTPUT_FILE.tmp"

# 4. Extract AI Tools from Tools
jq '
  # Create AI category if it doesn't exist
  if .categories.ai then . else
    .categories.ai = {"services": {}}
  end |
  
  # Define known AI tools (add more as needed)
  ["ChatGPT", "Bard", "Claude", "Anthropic", "OpenAI", "Midjourney", "DALL-E", "Stability", "Hugging Face", 
   "Perplexity", "Elevenlabs", "Character AI", "Copilot", "Gemini", "Leonardo"] as $aiTools |
  
  # Move matching tools to AI category
  if .categories.tools then
    . as $root |
    reduce ($aiTools[]) as $aiTool (
      .;
      . as $current |
      reduce ($current.categories.tools.services | keys[]) as $service (
        $current;
        if ($service | test($aiTool; "i")) then
          .categories.ai.services[$service] = $current.categories.tools.services[$service] |
          del(.categories.tools.services[$service])
        else . end
      )
    )
  else . end
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE.tmp2"
mv "$OUTPUT_FILE.tmp2" "$OUTPUT_FILE.tmp"

# 5. Move YouTube to video category and ensure it appears first
jq '
  # Find YouTube across all categories
  . as $root |
  reduce ($root.categories | keys[]) as $category (
    null;
    . // (
      $root.categories[$category].services | 
      to_entries | 
      map(select(.key | test("YouTube"; "i") or .key == "YouTube")) |
      if length > 0 then 
        {service: .[0], category: $category} 
      else 
        null 
      end
    )
  ) as $youtubeService |
  
  # If YouTube found, move it to video category
  if $youtubeService != null then
    # Make sure video category exists
    if .categories.video then . else 
      .categories.video = {"services": {}} 
    end |
    
    # Add YouTube to video category
    .categories.video.services["YouTube"] = $youtubeService.service.value |
    
    # Remove from original category if different
    if $youtubeService.category != "video" then
      del(.categories[$youtubeService.category].services[$youtubeService.service.key])
    else . end
  else . end
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE.tmp2"
mv "$OUTPUT_FILE.tmp2" "$OUTPUT_FILE.tmp"

# Final output with pretty formatting
jq --sort-keys '.' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE"
rm "$OUTPUT_FILE.tmp"
rm descriptions.json

echo "Data transformation complete. Output saved to $OUTPUT_FILE"