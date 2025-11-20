# Combined Character Encoding Fix Script
# Fixes various encoding issues in JavaScript files recursively

param(
    [string]$Path = ".",  # Default to current directory
    [string]$Filter = "*.js"
)

Write-Host "Character Encoding Fix Script" -ForegroundColor Cyan
Write-Host "Path: $Path" -ForegroundColor White
Write-Host "Filter: $Filter" -ForegroundColor White
Write-Host ""

$files = Get-ChildItem -Path $Path -Filter $Filter -Recurse -File
$totalFiles = $files.Count

if ($totalFiles -eq 0) {
    Write-Host "No files found matching the criteria!" -ForegroundColor Yellow
    exit
}

Write-Host "Found $totalFiles files to process..." -ForegroundColor Green
Write-Host ""

$processedCount = 0
$errorCount = 0

foreach ($file in $files) {
    $filePath = $file.FullName
    Write-Host "Processing: $filePath" -ForegroundColor Gray
    
    try {
        # Read file as bytes to handle any encoding
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        $encoding = [System.Text.Encoding]::UTF8
        $content = $encoding.GetString($bytes)
        
        # Remove UTF-8 BOM if present
        if ($content.StartsWith([char]0xFEFF)) {
            $content = $content.Substring(1)
            Write-Host "  Removed BOM" -ForegroundColor Yellow
        }
        
        # Character replacement mapping
        $replacements = @{
            # Dashes and hyphens
            [char]0x2011 = '-'  # Non-breaking hyphen
            [char]0x2012 = '-'  # Figure dash  
            [char]0x2013 = '-'  # En-dash
            [char]0x2014 = '-'  # Em-dash
            [char]0x2015 = '-'  # Horizontal bar
            
            # Double quotes
            [char]0x201C = '"'  # Left double quotation mark
            [char]0x201D = '"'  # Right double quotation mark
            [char]0x201E = '"'  # Double low-9 quotation mark
            [char]0x201F = '"'  # Double high-reversed-9 quotation mark
            [char]0x2033 = '"'  # Double prime
            [char]0x2036 = '"'  # Reversed double prime
            [char]0x275D = '"'  # Heavy double turned comma quotation mark ornament
            [char]0x275E = '"'  # Heavy double comma quotation mark ornament
            
            # Single quotes and apostrophes
            [char]0x2018 = "'"  # Left single quotation mark
            [char]0x2019 = "'"  # Right single quotation mark
            [char]0x201A = "'"  # Single low-9 quotation mark
            [char]0x201B = "'"  # Single high-reversed-9 quotation mark
            [char]0x2032 = "'"  # Prime
            [char]0x2035 = "'"  # Reversed prime
            [char]0x275B = "'"  # Heavy single turned comma quotation mark ornament
            [char]0x275C = "'"  # Heavy single comma quotation mark ornament
            
            # Other common problematic characters
            [char]0x2192 = "->" # Right arrow
            [char]0x2190 = "<-" # Left arrow
            [char]0x2191 = "^"  # Up arrow
            [char]0x2193 = "v"  # Down arrow
            [char]0x26A0 = "!!" # Warning sign
            [char]0x2026 = "..." # Ellipsis
        }
        
        # Perform all replacements
        $originalLength = $content.Length
        foreach ($replacement in $replacements.GetEnumerator()) {
            $char = $replacement.Key
            $replacementText = $replacement.Value
            if ($content.Contains($char)) {
                $content = $content.Replace($char, $replacementText)
            }
        }
        
        # Additional regex replacements for any remaining mojibake
        $content = $content -replace 'â€“', '-'
        $content = $content -replace 'â€”', '-' 
        $content = $content -replace 'â€‘', '-'
        $content = $content -replace '"', '"'
        $content = $content -replace 'â€', '"'
        $content = $content -replace 'â€˜', "'"
        $content = $content -replace 'â€™', "'"
        
        # Save with UTF-8 without BOM
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($filePath, $content, $utf8NoBom)
        
        $processedCount++
        Write-Host "  ✓ Cleaned and saved" -ForegroundColor Green
    }
    catch {
        $errorCount++
        Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=" * 50 -ForegroundColor Cyan
Write-Host "PROCESSING COMPLETE" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan
Write-Host "Total files processed: $processedCount" -ForegroundColor White
Write-Host "Errors encountered: $errorCount" -ForegroundColor White

if ($errorCount -eq 0) {
    Write-Host "All files successfully processed!" -ForegroundColor Green
} else {
    Write-Host "Some files had errors. Check the log above." -ForegroundColor Yellow
}