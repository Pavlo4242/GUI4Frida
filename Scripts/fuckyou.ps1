Get-ChildItem -Recurse -Filter "*.js" | ForEach-Object {
    $filePath = $_.FullName
    Write-Host "Processing: $filePath"
    
    try {
        # Read the file's text content with proper encoding
        $content = Get-Content -Path $filePath -Raw -Encoding UTF8
        
        # Replace various dash characters with standard hyphen
        $content = $content -replace [char]0x2013, '-'   # en-dash
        $content = $content -replace [char]0x2014, '-'   # em-dash  
        $content = $content -replace [char]0x2011, '-'   # non-breaking hyphen
        
        # Replace smart quotes with straight quotes using hex values
        $content = $content -replace [char]0x201C, '"'   # left double quote
        $content = $content -replace [char]0x201D, '"'   # right double quote
        $content = $content -replace [char]0x2018, "'"   # left single quote
        $content = $content -replace [char]0x2019, "'"   # right single quote
        
        # Write the cleaned content back to the file
        Set-Content -Path $filePath -Value $content -Encoding UTF8 -NoNewline
    }
    catch {
        Write-Host "Error processing $filePath : $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "--- SCRIPT COMPLETE ---" -ForegroundColor Green