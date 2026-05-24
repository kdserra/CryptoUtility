#!/bin/bash
set -e

NEXT_VERSION=$1
if [ -z "$NEXT_VERSION" ]; then
  echo "Error: Next release version not specified."
  exit 1
fi

echo "Preparing release $NEXT_VERSION..."

# 1. Find all publishable library csproj files dynamically
PROJS=$(find . -name "*.csproj" -not -path "*/bin/*" -not -path "*/obj/*" -exec grep -l "<PackageId>" {} + | sed 's|^\./||' | sort)

# 2. Update version tags in csproj files
for proj in $PROJS; do
  echo "Updating version in $proj..."
  sed -i "s|<Version>.*</Version>|<Version>$NEXT_VERSION</Version>|g" "$proj"
done

# 3. Update nuget version badge in README.md
echo "Updating README.md version badge..."
sed -i "s|badge/nuget-v[0-9.]*|badge/nuget-v$NEXT_VERSION|g" README.md

# 4. Build the solution in Release configuration
echo "Building solution..."
dotnet build -c Release

# 5. Publish Sample project
echo "Publishing sample binaries..."
dotnet publish CryptoUtility.Sample/CryptoUtility.Sample.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o out/publish/win-x64
dotnet publish CryptoUtility.Sample/CryptoUtility.Sample.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o out/publish/linux-x64

# 6. Pack library projects
for proj in $PROJS; do
  echo "Packing $proj..."
  dotnet pack "$proj" -c Release -o out/
done

# 7. Copy nupkg artifacts
mkdir -p release_artifacts
cp out/*.nupkg release_artifacts/
cp out/*.snupkg release_artifacts/ 2>/dev/null || true

# 8. Zip binary outputs dynamically
zip_dirs=""
for proj in $PROJS; do
  dir=$(dirname "$proj")
  if [ -d "$dir/bin/Release" ]; then
    zip_dirs="$zip_dirs $dir/bin/Release/"
  fi
done
if command -v zip >/dev/null 2>&1; then
  echo "Zipping binary outputs: $zip_dirs..."
  zip -r release_artifacts/CryptoUtility-binaries.zip $zip_dirs
else
  echo "Warning: 'zip' command not found. Skipping zip archive creation. (It will run in GitHub Actions where 'zip' is installed)"
fi

# 9. Copy sample binaries
cp out/publish/win-x64/CryptoUtility.Sample.exe release_artifacts/CryptoUtility.Sample-win-x64.exe
cp out/publish/linux-x64/CryptoUtility.Sample release_artifacts/CryptoUtility.Sample-linux-x64

echo "Release preparation complete!"
