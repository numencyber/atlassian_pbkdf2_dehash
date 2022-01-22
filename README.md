# Original Intention 
----------------------------------------
In one of the projects which is authorized we performed, we managed to gain the Atlassian Confluence server access by exploiting the CVE-2021-26084 RCE vulnerability to add a public key into their authorized ssh file.

We then proceed to perform the lateral movement by performing a localhost reconnaissance in which the database account password is in the confluence-home-directory/database folder.

One way how we can gain access to the web management portal is by updating the hashed password on the MySQL table:

````
## Get the administrator account, id
select u.id, u.user_name, u.active from cwd_user u
join cwd_membership m on u.id=m.child_user_id join cwd_group g on m.parent_id=g.id join cwd_directory d on d.id=g.directory_id
where g.group_name = 'confluence-administrators' and d.directory_name='Confluence Internal Directory';

## Change Password123123
UPDATE cwd_user SET credential = '{PKCS5S2}V1J8HcMvYsdtnETu2tjA1gFVQ1L3o+dAsNiooSAcSvpRcbkTR8K4Ha/iWgF145gk'  
WHERE id=393217;
````

---------------------------------------
# Problem
---------------------------------------
When you amend a confluence password, it will disallow users to log in to the other system because the internal IT staff are using the same login account and password, which will cause a problem when we want to perform lateral movement.

Through the MySQL database account, we managed to obtain the pbkdf2 hash value, and after studying the hash value, we can write a script called PBKDF2(Atlassian) hash atlassian_pbkdf2_dehash to perform a hash collision to gather the user's plaintext password,

After which, we manage to gain have access to the GitLab user account password through the plaintext password, find the code configuration file, multiple servers, and penetrate the intranet.

---------------------------------------
# Application 
````
python3 atlassian_pbkdf2_dehash.py -p <passwordfile> -f <hashfile>
````

---------------------------------------
# Operation Result Graph
![img.png](https://github.com/NumenCyberLabs/atlassian_pbkdf2_dehash/blob/main/img/img.png)
