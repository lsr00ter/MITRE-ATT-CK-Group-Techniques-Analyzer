import time

import pandas as pd
import requests
from bs4 import BeautifulSoup


def fetch_mitre_attack_groups():
    # URL of the MITRE ATT&CK groups page
    url = "https://attack.mitre.org/groups/"

    # Send HTTP request to the webpage
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content
        soup = BeautifulSoup(response.content, "html.parser")

        # Find the table containing the groups
        table = soup.find("table", class_="table-bordered")

        # Lists to store the data
        group_ids = []
        group_names = []

        # Extract data from table rows
        if table:
            rows = table.find_all("tr")[1:]  # Skip the header row
            for row in rows:
                cells = row.find_all("td")
                if len(cells) >= 2:
                    # Extract ID (first column)
                    group_id = cells[0].text.strip()
                    # Extract Name (second column)
                    group_name = cells[1].text.strip()

                    group_ids.append(group_id)
                    group_names.append(group_name)

            # Create a DataFrame
            groups_df = pd.DataFrame({"ID": group_ids, "Name": group_names})

            return groups_df
        else:
            print("Table not found on the webpage")
            return None
    else:
        print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
        return None


def enum_mitre_attack_group_techniques(mitre_groups):
    """
    Extract techniques used by MITRE ATT&CK groups by parsing the techniques table
    from each group's page on the MITRE ATT&CK website.

    The function parses the 'techniques-used' table which contains rows of different types:
    - Regular technique rows (parent techniques)
    - Sub-technique rows
    - Sub-technique continuation rows

    Args:
        mitre_groups (DataFrame): DataFrame containing group IDs and names

    Returns:
        DataFrame: DataFrame containing group IDs and their associated techniques
    """
    # Create a list to store techniques data for all groups
    all_techniques = []

    # Iterate through each group ID
    for group_id in mitre_groups["ID"]:
        print(f"Processing group: {group_id}")

        # Construct the URL for the specific group
        group_url = f"https://attack.mitre.org/groups/{group_id}/"

        # Send HTTP request to the group's page
        try:
            group_response = requests.get(group_url)

            # Check if the request was successful
            if group_response.status_code == 200:
                # Parse the HTML content
                group_soup = BeautifulSoup(group_response.content, "html.parser")

                # Look for the techniques table specifically with class 'techniques-used'
                techniques_table = group_soup.find("table", class_="techniques-used")

                if techniques_table:
                    # Get all rows after the header row
                    rows = techniques_table.find_all("tr")[1:]  # Skip the header row

                    # Keep track of the last seen technique ID for handling empty IDs
                    last_technique_id = ""

                    # Process each row
                    for row in rows:
                        # Get the row class to determine what type of row it is
                        row_class = row.get("class", [])
                        cells = row.find_all("td")

                        # Skip rows that don't have enough cells
                        if len(cells) < 2:
                            continue

                        # Different processing based on row type
                        if "technique" in row_class and "sub" not in row_class:
                            # Regular technique row (parent technique)
                            last_technique_id = process_technique_row(
                                row, group_id, all_techniques, last_technique_id
                            )
                        elif "sub" in row_class and "noparent" in row_class:
                            # Sub-technique row with domain info
                            last_technique_id = process_full_subtechnique_row(
                                row, group_id, all_techniques, last_technique_id
                            )
                        elif "sub" in row_class:
                            # Sub-technique continuation row (no domain info)
                            last_technique_id = process_continuation_subtechnique_row(
                                row, group_id, all_techniques, last_technique_id
                            )
                else:
                    print(f"No techniques table found for group {group_id}")
            else:
                print(
                    f"Failed to retrieve page for group {group_id}. Status code: {group_response.status_code}"
                )

            # Add a small delay to avoid overwhelming the server
            time.sleep(1)

        except Exception as e:
            print(f"Error processing group {group_id}: {str(e)}")

    # Create a DataFrame from the collected techniques
    techniques_df = pd.DataFrame(all_techniques)

    # Display the results
    if not techniques_df.empty:
        print("\nTechniques used by MITRE ATT&CK groups:")
        print(techniques_df)
        # Save to CSV
        techniques_df.to_csv("mitre_attack_techniques.csv", index=False)
        return techniques_df
    else:
        print("No techniques data was collected.")
        return None


def process_technique_row(row, group_id, all_techniques, last_technique_id):
    """
    Process a regular technique row (parent technique)

    Args:
        row: The table row to process
        group_id: The ID of the current group
        all_techniques: List to append the extracted technique info
        last_technique_id: The technique ID from the previous row

    Returns:
        The technique ID from this row (to be used as last_technique_id for the next row)
    """
    cells = row.find_all("td")

    # Extract the domain (typically first cell)
    domain = cells[0].text.strip()

    # Extract the technique ID (second cell with colspan=2)
    id_cell = cells[1]
    id_link = id_cell.find("a")
    technique_id = id_link.text.strip() if id_link else id_cell.text.strip()

    # If technique_id is empty, use the last seen technique ID
    if not technique_id:
        technique_id = last_technique_id

    # Extract the technique name (third cell when accounting for colspan)
    name_cell = cells[2]
    name_link = name_cell.find("a")
    technique_name = name_link.text.strip() if name_link else name_cell.text.strip()

    # Extract the use description (fourth cell when accounting for colspan)
    use_cell = cells[3]
    use_description = use_cell.text.strip()

    # Add to our list
    all_techniques.append(
        {
            "Group_ID": group_id,
            "Domain": domain,
            "Technique_ID": technique_id,
            "Technique_Name": technique_name,
            "Sub_Technique_ID": "",
            "Sub_Technique_Name": "",
            "Full_Technique_ID": technique_id,
            "Full_Technique_Name": technique_name,
            "Use": use_description,
        }
    )

    # Return the technique ID from this row (or the last one if this was empty)
    return technique_id


def process_full_subtechnique_row(row, group_id, all_techniques, last_technique_id):
    """
    Process a sub-technique row that includes domain info

    Args:
        row: The table row to process
        group_id: The ID of the current group
        all_techniques: List to append the extracted technique info
        last_technique_id: The technique ID from the previous row

    Returns:
        The technique ID from this row (to be used as last_technique_id for the next row)
    """
    cells = row.find_all("td")

    # Extract domain (first cell)
    domain = cells[0].text.strip()

    # Extract parent technique ID (second cell)
    id_cell = cells[1]
    id_link = id_cell.find("a")
    parent_technique_id = id_link.text.strip() if id_link else id_cell.text.strip()

    # If parent_technique_id is empty, use the last seen technique ID
    if not parent_technique_id:
        parent_technique_id = last_technique_id

    # Extract sub-technique ID (third cell)
    sub_id_cell = cells[2]
    sub_id_link = sub_id_cell.find("a")
    sub_technique_id = (
        sub_id_link.text.strip() if sub_id_link else sub_id_cell.text.strip()
    )

    # Extract the full technique name (fourth cell)
    name_cell = cells[3]

    # The name cell typically contains both parent and sub-technique names
    # Format is usually "Parent Technique: Sub-technique"
    full_name = name_cell.text.strip()

    # Try to parse parent and sub names from links
    parent_name_link = name_cell.find_all("a")[0] if name_cell.find_all("a") else None
    sub_name_link = (
        name_cell.find_all("a")[1] if len(name_cell.find_all("a")) > 1 else None
    )

    parent_name = parent_name_link.text.strip() if parent_name_link else ""
    sub_name = sub_name_link.text.strip() if sub_name_link else ""

    # Extract the use description
    use_cell = cells[4]
    use_description = use_cell.text.strip()

    # Build complete technique ID (e.g., T1087.001)
    full_technique_id = f"{parent_technique_id}{sub_technique_id}"

    # Add to our list
    all_techniques.append(
        {
            "Group_ID": group_id,
            "Domain": domain,
            "Technique_ID": parent_technique_id,
            "Technique_Name": parent_name,
            "Sub_Technique_ID": sub_technique_id,
            "Sub_Technique_Name": sub_name,
            "Full_Technique_ID": full_technique_id,
            "Full_Technique_Name": full_name,
            "Use": use_description,
        }
    )

    # Return the parent technique ID from this row
    return parent_technique_id


def process_continuation_subtechnique_row(
    row, group_id, all_techniques, last_technique_id
):
    """
    Process a sub-technique row that doesn't include domain info

    Args:
        row: The table row to process
        group_id: The ID of the current group
        all_techniques: List to append the extracted technique info
        last_technique_id: The technique ID from the previous row

    Returns:
        The technique ID from this row (to be used as last_technique_id for the next row)
    """
    cells = row.find_all("td")

    # These rows typically have empty first two cells
    # For the parent technique ID, we'll use the last seen technique ID
    parent_technique_id = last_technique_id

    # Extract sub-technique ID (third cell)
    sub_id_cell = cells[2]
    sub_id_link = sub_id_cell.find("a")
    sub_technique_id = (
        sub_id_link.text.strip() if sub_id_link else sub_id_cell.text.strip()
    )

    # Extract the technique name (fourth cell)
    name_cell = cells[3]

    # Parse parent and sub names from links
    links = name_cell.find_all("a")
    parent_name = links[0].text.strip() if links and len(links) > 0 else ""
    sub_name = links[1].text.strip() if links and len(links) > 1 else ""
    full_name = name_cell.text.strip()

    # Extract the use description
    use_cell = cells[4]
    use_description = use_cell.text.strip()

    # If we couldn't get a parent technique ID from the last_technique_id,
    # try to infer it from previously processed techniques
    if not parent_technique_id:
        for tech in reversed(all_techniques):
            if (
                tech["Group_ID"] == group_id
                and tech["Technique_ID"]
                and not tech["Sub_Technique_ID"]
            ):
                parent_technique_id = tech["Technique_ID"]
                break

    # Build complete technique ID
    full_technique_id = f"{parent_technique_id}{sub_technique_id}"

    # Add to our list
    all_techniques.append(
        {
            "Group_ID": group_id,
            "Domain": "Enterprise",  # Default to Enterprise since this is most common
            "Technique_ID": parent_technique_id,
            "Technique_Name": parent_name,
            "Sub_Technique_ID": sub_technique_id,
            "Sub_Technique_Name": sub_name,
            "Full_Technique_ID": full_technique_id,
            "Full_Technique_Name": full_name,
            "Use": use_description,
        }
    )

    # Return the parent technique ID (which is just the last_technique_id)
    return parent_technique_id


# Fetch the groups data
mitre_groups = fetch_mitre_attack_groups()

# Display the results
if mitre_groups is not None:
    print(mitre_groups)
    techniques_df = enum_mitre_attack_group_techniques(mitre_groups)
    if techniques_df is not None:
        print(f"Successfully collected {len(techniques_df)} technique entries")
    # Optionally save to CSV
    # mitre_groups.to_csv('mitre_attack_groups.csv', index=False)
