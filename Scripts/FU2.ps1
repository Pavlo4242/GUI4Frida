Get-ChildItem -Recurse -Filter "*.js" | ForEach-Object {
    $filePath = $_.FullName
    Write-Host "Processing: $filePath"
    
    try {
        # Detect encoding and read file
        $encoding = [System.Text.Encoding]::UTF8
        $content = [System.IO.File]::ReadAllText($filePath, $encoding)
        
        # Remove BOM if present (multiple BOM types)
        $bomChars = @([char]0xFEFF, [char]0xFFFE)
        foreach ($bom in $bomChars) {
            if ($content.StartsWith($bom)) {
                $content = $content.Substring(1)
                Write-Host "  Removed BOM from: $filePath" -ForegroundColor Yellow
                break
            }
        }
        
        # Character replacements
        $content = $content -replace '[\u2011\u2012\u2013\u2014\u2015]', '-'  # All dash types
        $content = $content -replace '[\u201C\u201D]', '"'                     # Smart double quotes
        $content = $content -replace '[\u2018\u2019]', "'"                     # Smart single quotes
        
        # Write back without BOM
        [System.IO.File]::WriteAllText($filePath, $content, [System.Text.UTF8Encoding]::new($false))
        
        Write-Host "  Success: $filePath" -ForegroundColor Green
    }
    catch {
        Write-Host "  Error: $filePath - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "--- ALL FILES PROCESSED ---" -ForegroundColor Green