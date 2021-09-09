---
layout: single
title: JsonWebToken
excerpt: JSON Web Token(JWT) is one of the commonly used methods for authorization. This is a kind of cookie that is generated using HMAC hashing or public/private keys. So unlike any other kind of cookie, it lets the website know what kind of access the currently logged in user has. The only special thing about JWT is that they are in JSON format(after decoding).
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/security.jpg
categories:
  - Blue Team
  - infosec
tags:
  - Blue Team
  - Red Team
---


JSON Web Token(JWT) is one of the commonly used methods for authorization. This is a kind of cookie that is generated using HMAC hashing or public/private keys. So unlike any other kind of cookie, it lets the website know what kind of access the currently logged in user has. The only special thing about JWT is that they are in JSON format(after decoding).

JWT can be divided into 3 parts separated by a dot(.)

1) Header:  This consists of the algorithm used and the type of the token.
```
{  "alg": "HS256", "typ": "JWT"}
```
alg could be HMAC, RSA, SHA256 or can even contain None value.

2) Payload: This is part that contains the access given to the certain user etc. This can vary from website to website, some can just have a simple username and some ID and others could have a lot of other details.

3) Signature: This is the part that is used to make sure that the integrity of the data was maintained while transferring it from a user's computer to the server and back. This is encrypted with whatever algorithm or alg that was passed in the header's value. And this can only be decrypted with a predefined secret(which should be difficult to)

Now to put all the 3 part together we base64 encode all of them separated by a dot(.) so it would look something like:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
Note: This example was taken from jwt.io and you should check that website out if you want to learn more about JWT.

## Exploitation

If used properly this is a very secure way of authorization but the problem is with using is "properly". A lot of developers misconfigure their system leaving it open to exploitation.

Now one of the methods to exploit this is to perform a brute force/dictionary attack and find the secret used for encrypting the JWT token and then used that to generate new tokens. But here we are not going to do that, we are going to see a very amazing way of exploiting this.

If you remember, in the Header section I said that the alg can be whatever the algorithm is used and also it can be None if no encryption is to be used. Now, this should not be used when the application is in production but again the problem of misconfiguration comes in and make the application vulnerable to this kind of attack. The attack is that an attacker can log in as low privilege user says guest and then get the JWT token for that user and then decode the token and edit the headers to use set alg value to None. This would mean that no encryption has to be used therefore the attacker wouldn't need to the secret used for encryption.

## Practical

Let's see this method in practice. For this challenge visit the port 5000.

It is a very simple login page and in that, you can log in via two users: user and user2. Now first let's try to login with the credentials of user:user . To do so first enter those credentials then click on the Authenticate button and then enable the capture in burp suite and then click on the Go button. In the burp tab, you should see a request to /protected ﻿and there you'll see the JWT token.

![image](https://user-images.githubusercontent.com/89842187/132728637-86c258c2-9b6f-4f3b-a4aa-81b418f6a369.png)

Now take this JWT token and then you can decode it part by part.

So if we decode the first part, which will do: {"typ":"JWT","alg":"HS256"}

and decoding the 2nd part, we will get: {"exp":1586620929,"iat":1586620629,"nbf":1586620629,"identity":1}

If you try to decode the 3rd part then you'll get some gibberish. But that is okay we only need the first and the second part.

Now if we notice the identity value that is probably being used to identify the user but if you'll just edit that then it won't work because as I said the 3rd part is encrypted. So to bypass this we will make changes in the header as well as the value of the identity.

Encode the following string with base64 and that will be our first part
```
{"typ":"JWT","alg":"NONE"}
```
For the second part, we'll encode the following string:

```
{"exp":1586620929,"iat":1586620629,"nbf":1586620629,"identity":2}
```
Notice how we changed the value of identity from 1  to 2.

Since we placed the alg value to None we don't have to add a 3rd part or the encrypted value so we can just put a dot(.) after 2nd part and leave it like that. So the final string would look like:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0K.eyJleHAiOjE1ODY3MDUyOTUsImlhdCI6MTU4NjcwNDk5NSwibmJmIjoxNTg2NzA0OTk1LCJpZGVudGl0eSI6MH0K.


```

Now open the developer's tools in your browser and edit the stored cookie of the website to this new one and then just press the Go button and you'll notice that it will prompt "Welcome user2: guest2".
In a similar manner, you can try to play and find other users on the website.



This kind of misconfiguration in the authentication system is common and could be exploited to escalate privileges or steal information.


