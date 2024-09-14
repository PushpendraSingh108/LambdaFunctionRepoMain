### Tagging Users:
1. The code processes each mapped account to list all IAM users.
2. For each user, it retrieves the existing tags.
3. It then checks if the user already has an "owner" tag or similar ("owner", "Owner", "OWNER").
4. If the "owner" tag exists and contains the domain "@precisely.com", the user is skipped.
5. If the "owner" tag exists but does not contain "@precisely.com", the user is skipped.
6. If the "owner" tag does not exist, it creates a new tag called "owner" with the combined owner emails and adds it to the user.

### Handling Existing "Owner" Tags:
7. If an "owner" tag exists and matches the domain "@precisely.com", the user is skipped and recorded in the skipped users list with the reason "Existing owner tag with value ...".
8. If an "owner" tag exists but does not match the domain "@precisely.com", the user is skipped and recorded in the skipped users list with the reason "Existing owner tag with non-@precisely.com value ...".
9. If no "owner" tag exists, a new "owner" tag is added with the appropriate owner emails, and the user is recorded in the tagged users list.
10. Epoch time is added to the filenames.
