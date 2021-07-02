<?php
echo "\nCount > ";
$count = trim(fgets(STDIN,1024));

for($x = 0; $x < $count; $x++){
$str = file_get_contents("http://namegenerators.org/fake-name-generator-us/");
$var = '/<div class="col2">(.*?)<\/div>/s';
preg_match_all($var, $str, $matches);
echo "\n[+] ************ CARD INFORMATION ************ [+]\n";
echo "Card-Name : ".str_replace("</span>", "", str_replace('<span class="name">', "", $matches[1][3]))."\n".
    "Card-Number : ".str_replace(" ", "", $matches[1][14])."\n".
    "Card-Cvv : ".$matches[1][16]."\n".
    "Card-Exp-Date : ".$matches[1][15]."\n".
    "Card-Address : ".$matches[1][8]."\n".
    "Card-Phone-Number : ".$matches[1][9]."\n";}?>