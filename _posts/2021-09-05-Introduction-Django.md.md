---
layout: single
title: Introduction to Django
excerpt: Learning Python can be extremely useful for penetration testers, and a simple understanding of its frameworks can be a key to success.
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/security.jpg
categories:
  - Blue Team
  - infosec
tags:
  - Blue Team

---


##  Introduction to Django

Learning Python can be extremely useful for penetration testers, and a simple understanding of its frameworks can be a key to success. In this lesson, we are going to learn about one of the best ones ever made: Django. 

Django is a high-level Python web framework that enables rapid development of secure and maintainable websites. It allows you to develop websites and web applications in a matter of hours.

Django can automatically compile HTML code, therefore making it possible for anyone without any advanced knowledge in markup languages to develop a website. Additionally, Django is arguably one of the most secure developing frameworks, which in the right configuration, can strongly resist against SQL injections and XSS.

All in all, if you are familiar with Python and considering creating a website, Django can be a really good choice. As for penetration tester, it is important to understand the basic structure of Django-powered websites in order to be able to identify possible weaknesses and mistakes a developer can make.


Attention! If you have absolutely no experience in python, I recommend doing this room on python basics: "Intro To Python"

For this room, we are going to use Python 3. (Any 3.x.x works here) with Django 2.2

Install Django by running this command:
```
pip3 install Django==2.2.12
```


Now we are ready to create and properly configure our first website.

Make a directory for your project files and navigate there with the command prompt.

run django-admin startproject {project_name} in order to start your project. (Replace {project_name} with your prefered name).

Run python3 manage.py migrateto automatically configure new files.

After creating the project you can see that Django creates a file manage.py and a file directory named after your project.

manage.py is a command-line utility that lets you interact with your Django project in various ways. It is especially handy in creating web-apps, managing databases, and most importantly running the server.

Basic syntax for using this utility is python3 manage.py {command}

> runserver

Runserver is the most important command used with manage.py; It allows you to deploy your website on the server. Django has a wonderful feature that allows you to instantly see changes made on the website without restarting it. (It is only necessary to restart runserver command when adding a new app).

Run this command and navigate to your website with IP given in the outline. You should see a page like this:


![image](https://user-images.githubusercontent.com/89842187/132133740-bf012641-e995-4789-b710-e110fdad2294.png)



Note: If you are willing to run the server to your local network, just add 0.0.0.0:8000 after runserver command. (In case if you get an error afterward, just go to settings.py located your websites folder and add this address to ALLOWED_HOSTS)

![image](https://user-images.githubusercontent.com/89842187/132133771-a673f6da-8e53-4cad-9c70-0148b0e8a401.png)


> createsuperuser

This command allows you to create an admin account for your Django web admin panel. 

Run this command and access the panel at IP:8000/admin

![image](https://user-images.githubusercontent.com/89842187/132133776-8ebad27c-547e-4bd2-9cde-681ebb2aafb0.png)


> startapp

Startapp allows you to initialize an app for your project. Django projects can have infinite number of apps. Basic syntax:

python3 manage.py startapp {app_name}

How would we create an app called Forms? 

```
python3 manage.py startapp Forms
```

How would we run our project to a local network?

```
python3 manage.py runserver 0.0.0.0:8000
```

## Creating a website

Now, let's go ahead and create a very simple app: 

1. Create an app using a command from Unit 2 and call it whatever you like. I will be using 'Articles' for this lesson.

2. Head over to settings.py and include your app name in *INSTALLED_APPS*:

![image](https://user-images.githubusercontent.com/89842187/132133788-eaf528df-cd08-4ab3-9a28-4b19e96380dd.png)

Head over to urls.py (located in the main folder!) and include a path to your app there:

![image](https://user-images.githubusercontent.com/89842187/132133794-38e4d93d-60a0-42c3-88ec-be02876272dc.png)


Note that {app_name} should be replaced with your app's name.

4. Migrate your changes by running python3 manage.py migrate

Your app is now located in the https://IP:8000/{app_name} 

After successful app creation let's move over to the app directory and proceed there. As seen, Django automatically creates files inside your app folder. We are going to go through their purposes as we continue creating our website.

For now, create a file urls.py which will be especially handy in the closest future.

Generally speaking, Django-driven websites operate in this way:

![image](https://user-images.githubusercontent.com/89842187/132133805-93a249da-84fe-45a7-aa06-a664cf91cced.png)


urls.py is responsible for accepting and redistributing incoming HTTP requests via views.py

![image](https://user-images.githubusercontent.com/89842187/132133808-b8322d1e-95e1-4115-9f90-a8871b8531d4.png)

Basic syntax for urls.py can be seen on the screenshot above. 

We create a variable called urlpatterns in which we state names of our directories. views.index calls index function from views.py to be executed therefore creating some output response for HTTP request.

For example, if we are willing to create a directory called "archive", with function "main", we would include this in urls.py:

```
path('archive/', views.main, name ='main')


```

NOTE: Paths with blank directory ('') are going to call the function whenever the app is accessed at https://IP/{app_name}; any other directories are going to extend the link, for example, the archives directory I used above would be located inhttps://IP/articles/archive.

views.py is responsible for carrying out functions which are called using urls.py

Now let's create a simple HTTP response function for our app.

The syntax is pretty easy for this one. All you have to do is create a function with a certain name which you will be referring to in urls.py 

Here's an example of a function that returns "Hello, world!" message:

![image](https://user-images.githubusercontent.com/89842187/132133828-7a2b34b5-92cf-434d-8238-6f634587f564.png)


Note that in this case the function is called index, and so in order to make it work you need to put this line into your urls.py

path('', views.index, name='index'),

![image](https://user-images.githubusercontent.com/89842187/132133835-8ce1bd84-62b7-4c94-87e3-6051e5c74159.png)


Now navigate to your http://IP:8000/{app_name} and see if "Hello, world!" popped out.

By this point, we were able to create a really simple website example that returns a text message. We are also able to create different apps and expand them with directories and went through the web part of Django server. 

Obviously, a simple HTTP Response isn't enough to properly display content. Django is able to automatically generate HTML markdown if properly told so. Templates are the ones who help us with that. 

Without further ado let's create a folder named templates in your app's folder and place a file named base.html into it. Base.html is going to play a role of a simply configured HTML example which in the long run, allows us to omit work with HTML. 

Content of base.html is pretty basic and stays the same most of the time:

![image](https://user-images.githubusercontent.com/89842187/132133840-471eb34b-bb46-4216-885c-7401ba13e8be.png)

Now, create some another blank HTML file (index.html) and include this code in it:

![image](https://user-images.githubusercontent.com/89842187/132133843-51b5d2f8-1841-4b4a-a044-dd95a486814e.png)


As seen here, it uses base.html as its basis and allows us to input any simple or slightly HTML-marked text in-between { extends 'base.html'%} and {endblock}. Try changing Hello World to some other text and now we are ready to make it work!

Remember what file is responsible for storing functions? views.py! 

Head over there and change the index function to this code which will automatically render your template from index.html

![image](https://user-images.githubusercontent.com/89842187/132133851-ef6e03da-b20a-417a-97dd-b7a02480d454.png)


Now check your text at http://IP:8000/{app_name}

You can create different templates for different functions and use them separately. For example, if you are creating a blog website, you might want to make templates for articles and homepage separately.

> In case if it was hard for you to follow the guide, or you have any errors, head over to Unit 4 and find a github link there. I'll upload an exact example of what I was talking about here so you can compare it with your code and easily troubleshoot.
