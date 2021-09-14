---
layout: single
title: Attack Types Burpsuite
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/security.jpg
categories:
  - Blue Team
  - infosec
  - Red Team
tags:
  - Blue Team
  - Red Team
---

# Battering Ram

Battering ram takes one set of payloads (e.g. one wordlist). Unlike Sniper, the Battering ram puts the same payload in every position rather than in each position in turn.

Let's use the same wordlist and example request as we did in the last task to illustrate this.

```

POST /support/login/ HTTP/1.1
Host: 10.10.191.141
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://10.10.191.141
Connection: close
Referer: http://10.10.191.141/support/login/
Upgrade-Insecure-Requests: 1

username=§pentester§&password=§Expl01ted§
```

If we use Battering ram to attack this, Intruder will take each payload and substitute it into every position at once.

With the two positions that we have above, Intruder would use the three words from before (burp, suite, and intruder) to make three requests:

![image](https://user-images.githubusercontent.com/89842187/133293504-80533289-7bbc-447b-966c-710194cbbf47.png)

As can be seen in the table, each item in our list of payloads gets put into every position for each request. True to the name, Battering ram just throws payloads at the target to see what sticks.


# Pitchfork

Pitchfork is the attack type you are most likely to use. It may help to think of Pitchfork as being like having numerous Snipers running simultaneously. Where Sniper uses one payload set (which it uses on every position simultaneously), Pitchfork uses one payload set per position (up to a maximum of 20) and iterates through them all at once.

This type of attack can take a little time to get your head around, so let's use our bruteforce example from before, but this time we need two wordlists:

- Our first wordlist will be usernames. It contains three entries: joel, harriet, alex.
- Let's say that Joel, Harriet, and Alex have had their passwords leaked: we know that Joel's password is J03l, Harriet's password is Emma1815, and Alex's password is Sk1ll.


We can use these two lists to perform a pitchfork attack on the login form from before. The process for carrying out this attack will not be covered in this task, but you will get plenty of opportunities to perform attacks like this later!

When using Intruder in pitchfork mode, the requests made would look something like this:

![image](https://user-images.githubusercontent.com/89842187/133293767-268bbf2b-304a-4a62-aaab-a9eadf30980b.png)

See how Pitchfork takes the first item from each list and puts them into the request, one per position? It then repeats this for the next request: taking the second item from each list and substituting it into the template. Intruder will keep doing this until one (or all) of the lists run out. Ideally, our payload sets should be identical lengths when working in Pitchfork, as Intruder will stop testing as soon as one of the lists is complete. For example, if we have two lists, one with 100 lines and one with 90 lines, Intruder will only make 90 requests, and the final ten items in the first list will not get tested.

This attack type is exceptionally useful when forming things like credential stuffing attacks (we have just encountered a small-scale version of this). We will be looking more into these later in the room.


# Cluster Bomb
Like Pitchfork, Cluster bomb allows us to choose multiple payload sets: one per position, up to a maximum of 20; however, whilst Pitchfork iterates through each payload set simultaneously, Cluster bomb iterates through each payload set individually, making sure that every possible combination of payloads is tested.

Again, the best way to visualise this is with an example.

Let's use the same wordlists as before:

- Usernames: joel, harriet, alex.
- Passwords: J03l, Emma1815, Sk1ll.
But, this time, let's assume that we don't know which password belongs to which user. We have three users and three passwords, but we don't know how to match them up. In this case, we would use a cluster bomb attack; this will try every combination of values. The request table for our username and password positions looks something like this:

![image](https://user-images.githubusercontent.com/89842187/133293951-6bb6de26-d1f7-40d1-bfbb-32e4cb5f8c02.png)

Cluster Bomb will iterate through every combination of the provided payload sets to ensure that every possibility has been tested. This attack-type can create a huge amount of traffic (equal to the number of lines in each payload set multiplied together), so be careful! Equally, when using Burp Community and its Intruder rate-limiting, be aware that a Cluster Bomb attack with any moderately sized payload set will take an incredibly long time.

That said, this is another extremely useful attack type for any kind of credential bruteforcing where a username isn't known.


# CSRF Token

Configure the positions the same way as we did for bruteforcing the support login:

- Set the attack type to be "Pitchfork".
- Clear all of the predefined positions and select only the username and password form fields. The other two positions will be handled by our macro.

![image](https://user-images.githubusercontent.com/89842187/133321098-7a3f067d-0272-477a-91e7-69627a2e1bbb.png)


With the username and password parameters handled, we now need to find a way to grab the ever-changing loginToken and session cookie. Unfortunately, Recursive Grep won't work here due to the redirect response, so we can't do this entirely within Intruder -- we will need to build a macro.

Macros allow us to perform the same set of actions repeatedly. In this case, we simply want to send a GET request to /admin/login/.

Fortunately, setting this up is a very easy process.

- Switch over to the "Project Options" tab, then the "Sessions" sub-tab.
- Scroll down to the bottom of the sub-tab to the "Macros" section and click the "Add" button.
- The menu that appears will show us our request history. If there isn't a GET request to http://10.10.59.180/admin/login/ in the list already, navigate to this location in your browser and you should see a suitable request appear in the list.
- With the request selected, click Ok.
- Finally, give the macro a suitable name, then click "Ok" again to finish the process.

Now that we have a macro defined, we need to set Session Handling rules that define how the macro should be used.

- Still in the "Sessions" sub-tab of Project Options, scroll up to the "Session Handling Rules" section and choose to "Add" a new rule.
- A new window will pop up with two tabs in it: "Details" and "Scope". We are in the Details tab by default.

- Fill in an appropriate description, then switch over to the Scope tab.
- In the "Tools Scope" section, deselect every checkbox other than Intruder -- we do not need this rule to apply anywhere else.
- In the "URL Scope" section, choose "Use suite scope"; this will set the macro to only operate on sites that have been added to the global scope (as was discussed in Burp Basics). If you have not set a global scope, keep the "Use custom scope" option as default and add http://10.10.59.180/ to the scope in this section.

![image](https://user-images.githubusercontent.com/89842187/133321317-cb46cd66-a4c0-4f06-9b4a-2e87831abb91.png)


Now we need to switch back over to the Details tab and look at the "Rule Actions" section.

- Click the "Add" button -- this will cause a dropdown menu to appear with a list of actions we can add.
- Select "Run a Macro" from this list.
- In the new window that appears, select the macro we created earlier.


As it stands, this macro will now overwrite all of the parameters in our Intruder requests before we send them; this is great, as it means that we will be getting the loginTokens and session cookies added straight into our requests. That said, we should restrict which parameters and cookies are being updated before we start our attack:

- Select "Update only the following parameters", then click the "Edit" button next to the input box below the radio button.
- In the "Enter a new item" text field, type "loginToken". Press "Add", then "Close".
- Select "Update only the following cookies", then click the relevant "Edit" button.
- Enter "session" in the "Enter a new item" text field, press "Add", then "Close".
- Finally, press "Ok" to confirm our action.


You should now have a macro defined that will substitute in the CSRF token and session cookie. All that's left to do is switch back to Intruder and start the attack!

## Sequencer

Sequencer is one of those tools that rarely ever gets used in CTFs and other lab environments but is an essential part of a real-world web app penetration test.

In short, Sequencer allows us to measure the entropy (or randomness, in other words) of "tokens" -- strings that are used to identify something and should, in theory, be generated in a cryptographically secure manner. For example, we may wish to analyse the randomness of a session cookie or a Cross-Site Request Forgery (CSRF) token protecting a form submission. If it turns out that these tokens are not generated securely, then we can (in theory) predict the values of upcoming tokens. Just imagine the implications of this if the token in question is used for password resets...

Let's start, as ever, by taking a look at the Sequencer interface:

![image](https://user-images.githubusercontent.com/89842187/133334687-d3fd7650-a99d-4f2a-8fa2-1f771115687d.png)

There are two main methods we can use to perform token analysis with Sequencer:

- Live capture is the more common of the two methods -- this is the default sub-tab for Sequencer. Live capture allows us to pass a request to Sequencer, which we know will create a token for us to analyse. For example, we may wish to pass a POST request to a login endpoint into Sequencer, as we know that the server will respond by giving us a cookie. With the request passed in, we can tell Sequencer to start a live capture: it will then make the same request thousands of times automatically, storing the generated token samples for analysis. Once we have accumulated enough samples, we stop Sequencer and allow it to analyse the captured tokens.
- Manual load allows us to load a list of pre-generated token samples straight into Sequencer for analysis. Using Manual Load means we don't have to make thousands of requests to our target (which is both loud and resource intensive), but it does mean that we need to obtain a large list of pre-generated tokens!
We will be focusing on live captures in this room.


The Request Timer extension (Written by Nick Taylor) allows us to log the time that each request we send takes to receive a response; this can be extremely useful for discovering the presence of (and exploiting) time-based vulnerabilities. For example, if a login form takes an extra second to process requests that contain a valid username than it does for accounts that do not exist, then we can quickly generate a list of possible usernames and use the difference in times to see which usernames are valid.


#  Jython / JRuby
https://www.jruby.org/download
https://www.jython.org/download
If we want to use Python modules in Burp Suite, we need to have downloaded and included the separate Jython Interpreter JAR file. The Jython interpreter is a Java implementation of Python. The website gives us the option to either install Jython to our system or download it as a standalone Java archive (JAR). We need it as a standalone archive to integrate it with Burp.

Note: we can do the same thing with Ruby modules and the JRuby integration; however, we will not cover this here as: A) Python modules are much more common and B) it's exactly the same process for both.

First up, we need to download an up-to-date copy of the Jython JAR archive from the Jython website . We are looking for the Jython Standalone option:

![image](https://user-images.githubusercontent.com/89842187/133336232-f5db8449-6eeb-4847-aa97-fa1cf4ec155e.png)

Save the JAR file somewhere on your disk, then switch to the "Options" sub-tab in Extender.

Scroll down to the "Python Environment" section, and set the "Location of Jython standalone JAR file" to the path of the archive:
![image](https://user-images.githubusercontent.com/89842187/133336250-e5607912-f876-4076-95db-d081606e6186.png)

Simple as that, we can now install Python modules from the BApp store!

This is a very simple step that significantly increases the number of extensions available to us.

Note: Due to the multi-platform nature of Java, the exact same steps will work for adding Jython to Burp Suite on any operating system.


https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension

