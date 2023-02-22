#!/bin/bash

LICENSE_HEADER_TEMPLATE="/*
 * This file is part of [PROJECT] distributed at [REPO]
 * Copyright (C) 2020-[YEAR] [OWNER]
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */"

PROJECT="Nodle Smart Missions"
REPO="https:\/\/github.com\/NodleCode\/smart-mission-contracts"
OWNER="Nodle International"
YEAR=$(date +"%Y")

LICENSE_HEADER=$(echo "$LICENSE_HEADER_TEMPLATE" | sed -e "s/\[PROJECT\]/$PROJECT/g" -e "s/\[REPO\]/$REPO/g" -e "s/\[OWNER\]/$OWNER/g" -e "s/\[YEAR\]/$YEAR/g")

# Find all Rust files in the current directory and its subdirectories
FILES=$(find . -name "*.rs")

# Loop over the files and add the license header
for FILE in $FILES; do
  # Check if this is a build file
  if echo "$FILE" | grep -q "target\/ink\|target\/target\/release\|target\/debug\|target\/dylint"; then
    echo "Skipping build file: $FILE"
    continue
  fi

  # Check if the file already has a license header
  if grep -q "* This file is part of" "$FILE"; then
    echo "Skipping file: $FILE (already has license header)"
    continue
  fi

  echo "Adding license header to file: $FILE"
  TEMP_FILE=$(mktemp)
  echo "$LICENSE_HEADER" > "$TEMP_FILE"
  echo "" >> "$TEMP_FILE"
  cat "$FILE" >> "$TEMP_FILE"
  mv "$TEMP_FILE" "$FILE"
done
