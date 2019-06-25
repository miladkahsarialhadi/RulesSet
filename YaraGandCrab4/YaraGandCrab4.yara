import "hash"

rule GandCrabRansomware
{
	meta:
    		author = "Milad Kahsari Alhadi"
		description = "This rule is created to detect GandCrab v4."
		cape_type = "Ransomware Executable"
		in_the_wild = true

	strings:
		$string1 = "@hashbreaker Daniel J. Bernstein let's dance salsa <3" wide
		$string2 = "GandCrabGandCrabnomoreransom.coinomoreransom.bit"
		$string3 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" wide
		$string4 = "KRAB-DECRYPT.txt" wide
		$string5 = "jopochlen"
		
	condition:
		hash.md5(0, filesize) == "F876735F6D4F076DFB148C63C4BA5A3A" or any of ($string*) 
		
}
