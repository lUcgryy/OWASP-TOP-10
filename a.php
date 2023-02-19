<?php
function sanitizeFileName($fileName) {
    // Remove any characters that are not letters, numbers, or dots
    $fileName = preg_replace('/[^a-zA-Z0-9.]/', '', $fileName);
    
    // Remove any path separators
    $fileName = str_replace(array('/', '\\'), '', $fileName);

    return $fileName;
}

// Example usage
$fileName = "../../etc/passwd";
$fileName = sanitizeFileName($fileName);
$filename = ltrip($fileName, '.');
echo $fileName;
?> 