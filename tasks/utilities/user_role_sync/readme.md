## Running User Role Sync Task

This 128iid task allows you to maintain your User and Role lists within Kenna through an automated process, using a CSV export from your source system.

To run this task you need the following information: 

1. Kenna API Token/Key
1. User-Role CSV File

This task will ingest the supplied CSV File and align the Kenna Users and Roles to match. There are a few optional parameters that can be supplied to provide more detailed functionality. It will create users, and roles as needed.  Any roles created will have read-only permissions and will need to be configured by the Kenna Administrator.  This task also has the capability to remove users when they exist in Kenna, but not in the currently supplied CSV File.

## Command Line

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| kenna_api_key | true | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| csv_file | true | User Role Data - User Supplied | n/a |
| email_column | false | Column Name for email address within 'csv_file'. (case-sensitive) | EmailAddress |
| firstname_column | false | Column Name for first name within 'csv_file'. (case-sensitive) | FirstName |
| lastname_column | false | Column Name for last name within 'csv_file'. (case-sensitive) | LastName |
| role_column | false | Column Name for role within 'csv_file'. (case-sensitive) | ADGroup |
| remove_users | false | Optional boolean parameter to remove users not in data file from Kenna system. | false |
| role_exclusions | false | Optional parameter. Comma-delimited list of role IDs to exclude from updates. | n/a |
| debug | false | Optional Boolean Debug Flag | n/a |

## Syntax Examples:

**Minimal Example:**
```
docker run -it --rm 128iid:latest task=user_role_sync csv_file=path/to/file.csv kenna_api_key=xxxxxxxxx
```
This example will run with all defaults, assuming the column names match defaults. It will not remove users from Kenna, or exclude any roles from being modified, except for administator, which is always excluded.

**Mapping Columns Example:**
```
docker run -it --rm 128iid:latest task=user_role_sync csv_file=path/to/file.csv kenna_api_key=xxxxxxxxx email_column=Email firstname_column=First lastname_column=Last
```  
This example shows how to manually map column names when needed. You can map some columns, all columns, or none.

**Remove Users Example:**
```
docker run -it --rm 128iid:latest task=user_role_sync csv_file=path/to/file.csv kenna_api_key=xxxxxxxxx remove_users=true
```
This example shows how to specify the **remove_users** flag. **WARNING:** this option can be destructive and possibly remove users from your Kenna system.

**Role Exclusion Example:**

```
docker run -it --rm 128iid:latest task=user_role_sync csv_file=path/to/file.csv kenna_api_key=xxxxxxxxx role_exclusions=1,23423
```
This example shows how to specify role IDs within Kenna that should be excluded from any updates. These should be supplied by Kenna Role ID. Multiple IDs can be included in a comma-separated list. You can find the role IDs within Kenna by opening the edit screen for a role and pulling it from the URL.

**Example:** ```https://mykenna.denist.dev/settings/roles/xxxxx/edit```

## CSV File Example:
The CSV File is expected to have the follow format:

| Email | FirstName | LastName | ADGroup |
| --- | --- | --- | --- |
| user1@example.com | User1 | FirstLast | Role1,Role2 |
| user2@example.com | User2 | SecondLast | Role1 |
| user3@example.com | User3 | ThirdLast | Role1 |
| user4@example.com | User4 | FourthLast | Role2 |
| user5@example.com | User5 | FifthLast | Role3 |
| user6@example.com | User6 | SixthLast | Role4 |

If viewed in a simple text editor the CSV example above would look like the following:
```
Email,FirstName,LastName,ADGroup
user1@example.com,User1,FirstLast,"Role1,Role2"
user2@example.com,User2,SecondLast,Role1
user3@example.com,User3,ThirdLast,Role1
user4@example.com,User4,FourthLast,Role2
user5@example.com,User5,FifthLast,Role3
user6@example.com,User6,SixthLast,Role4
```

**Note:** Comma-delimited roles must be enclosed in double-quotes (_standard CSV text qualifier_)


