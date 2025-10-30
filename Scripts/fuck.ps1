Get-ChildItem -Recurse -Filter *.js | ForEach-Object {
    $filePath = $_.FullName
    Write-Host "Processing: $filePath"
    
    # Read the file content
    $content = Get-Content $filePath -Raw

    # Perform the replacements
    $content = $content -replace '–', '-'
    $content = $content -replace '—', '-'
    $content = $content -replace '‑', '-'
    $content = $content -replace '“', '"'
    $content = $content -replace '”', '"'
    $content = $content -replace '‘', "'"
    $content = $content -replace '’', "'"

    # Write the content back to the file using UTF-8
    Set-Content -Path $filePath -Value $content -Encoding utf8
}

Write-Host "--- SCRIPT COMPLETE ---"