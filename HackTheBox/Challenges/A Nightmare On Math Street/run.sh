#!/bin/sh
{
    while read -r line <&3; do echo "$line"
      if [[ "$line" =~ "= ?" ]]; then #If we get the line containing the equation (by detecting the last characters)
        equation=$(echo "$line" | sed -e 's/.*: \(.*\) = ?/\1/') #Extract the equation
        flag=0
        while grep -o '\(([0-9]\+\( \(\*\|+\) [0-9]\+)\)\+\)' | head -1 > /dev/null; do #grep will detect all + or * operations in parenthesis between numbers
            equation=$(echo "$equation" | sed -E 's/([0-9]+( \+ [0-9]+)+)/(\1)/g') # All numbers to be added will be put around parenthesis
            fact=$(echo "$equation" | grep -oP '\([0-9]+( \+ [0-9]+)+\)' | head -1 | tr -d '()') # Extract the factors, the numbers to multiply or add. Remove also any () around these numbers
            if [ -z "$fact" ] ; then #If there are not numbers to add in parenthesis, go ahead to check for number to multiply
                flag=0 #Don't still go out, because maybe there are parenthesis with to multiply that we process below
            else
                flag=1
                num=$(echo "$fact" | bc)
                equation=$(echo "$equation" | sed "s/($fact)/$num/g")
                for j in {1..5}; do equation=$(echo "$equation" | sed "s/($num)/$num/g");done #Remove all the brackets around a single number, i.e. (((13)))
            fi
            fact=$(echo "$equation" | grep -oP '\([0-9]+( \* [0-9]+)+\)' | head -1 | tr -d '()') 
            if [ -z "$fact" ] && [ "$flag" -eq "0" ] ; then echo "$equation"; break
            elif [ "$flag" -ne "1" ]; then
                num=$(echo "$fact" | bc)
                fact=$(echo "${fact//\*/\\*}") #Needed for sed replacing
                equation=$(echo "$equation" | sed "s/($fact)/$num/g")
                for j in {1..5}; do equation=$(echo "$equation" | sed "s/($num)/$num/g");done #Remove all the brackets around a single number, i.e. (((13)))
            fi
        done <<< $equation
        echo "$equation" | bc >&3 #Send the result of this command to the server
      fi
    done
} 3<>/dev/tcp/138.68.182.130/30993 #Server assigned to device 3
