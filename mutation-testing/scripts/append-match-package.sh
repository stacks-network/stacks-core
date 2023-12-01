#!/bin/bash

# the append-match-package.sh
## goes through each line in the output and based on the package ( first element before /)
### verifies the line with the other lines in that specific folder
#### in our case folder_name == package_name


# goes through each PR file line by line
# for each first_element/the_rest_of_the_line goes through it
## search in that specific folder on all 4 files
## if it is matchy, remove it from that file
## based on the file it was taken from, append it to the same file in the STABLE folder


PR_FOLDER="../temp/mutants.out"
STABLE_FOLDER_PARENT="../packages-output"
FILES=("caught.txt" "missed.txt" "timeout.txt" "unviable.txt")

echo "Starting script..."
echo "PR Folder: $PR_FOLDER"
echo "STABLE Folder: $STABLE_FOLDER_PARENT"
echo "Files to process: ${FILES[*]}"

# Iterate over the specified files
for file in "${FILES[@]}"; do
    pr_file="$PR_FOLDER/$file"

    echo "Processing file: $file"

    # Check if PR file exists and is not empty
    if [[ -s "$pr_file" ]]; then
        # Read each line from the PR file
        while IFS= read -r line; do
            echo "Reading line from PR file: $line"

            # Extract the package from which the line is coming from
            local_package=${line%%/*}

            # Extract the after the number line without the line number and escape it for awk
            # Escape the variables for use in a sed pattern
            var_1=$(echo "$line" | sed -E 's/^(.+):[0-9]+:[^:]+/\1/')
            escaped_var_1=$(sed 's/[][/.^$]/\\&/g' <<< "$var_1")

            var_2=$(echo "$line" | sed -E 's/^[^:]+:[0-9]+:(.+)/\1/')
            escaped_var_2=$(sed 's/[][/.^$]/\\&/g' <<< "$var_2")

            regex="${escaped_var_1}.*${escaped_var_2}"

            # Iterate over each file in the STABLE folder combined with local_package
            for target_file in "${FILES[@]}"; do
                target_path="$STABLE_FOLDER_PARENT/$local_package/$target_file"
                echo "Checking against STABLE file: $target_path"

                # Use sed to remove lines matching the pattern
                sed "/$regex/d" "$target_path" > temp_file && mv temp_file "$target_path"
            done

            # Append PR line to the corresponding package and file
            echo "$line" >> "$STABLE_FOLDER_PARENT/$local_package/$file"
            
        done < "$pr_file"
    else
        echo "PR file $pr_file is empty or does not exist, skipping..."
    fi
done

echo "Script completed."
