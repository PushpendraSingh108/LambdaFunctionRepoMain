##Tagging Users:-----
#The code processes each mapped account to list all IAM users.
#For each user, it retrieves the existing tags.
#It then checks if the user already has an "owner" tag or similar ("owner", "Owner", "OWNER").
#If the "owner" tag exists and contains the domain "@precisely.com", the user is skipped.
#If the "owner" tag exists but does not contain "@precisely.com", the user is skipped.
#If the "owner" tag does not exist, it creates a new tag called "owner" with the combined owner emails and adds it to the user.
##Handling Existing "Owner" Tags:---
#If an "owner" tag exists and matches the domain "@precisely.com", the user is skipped and recorded in the skipped users list with the reason "Existing owner tag with value ...".
#If an "owner" tag exists but does not match the domain "@precisely.com", the user is skipped and recorded in the skipped users list with the reason "Existing owner tag with non-@precisely.com value ...".
#If no "owner" tag exists, a new "owner" tag is added with the appropriate owner emails, and the user is recorded in the tagged users list.
# epoch time is added to the filenames
