# SecurityProjects


## Python3_LDAP_Pull

This is one of the first python scripts I ever officially blogged about (so it may not be exactly very efficient as it's quite old.

It is a script I wrote to pull large data sets of Active Directory data using Python 3 and ldap3. I didn't see any blogs that fulfilled my particular use case so I figured I would post a working version that I have. I have truncated all sensitive information out with <TRUNC> so be sure to replace that with the respective information (i.e. server/OU information). Most of the portions of the script are commented and hopefully contain enough information to be understandable and manipulated by people like me that were stuck with the examples given in the ldap3 documentation and various github/blog posts.

I would say the primary issue for me was that I had to enable paging for ldap3 to pull the results correctly and the documentation confused me about as to the best way to do this. I also have to pull from multiple OUs so I had to get that into the loop as well.

If you have any questions please feel free to comment on the blog post (https://www.ryanglynn.com/2017/08/23/python3_script_thousands_of_entries_ldap3/) or contact me via the contact page. 
