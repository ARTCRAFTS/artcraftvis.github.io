---
layout: single
title: Introducción a Python
excerpt: "title: Python es un lenguaje de programación interpretado cuya filosofía hace hincapié en la legibilidad de su código. Se trata de un lenguaje de programación multiparadigma, ya que soporta parcialmente la orientación a objetos, programación imperativa y, en menor medida, programación funcional."
classes: wide

categories:
  - Programming
  - infosec
tags:
  - Programming

---
- # Introducción a Python.
     * [Strings](strings)
     * [Math](#Math)
     * [Variables](#Variables)
     * [Functions](#Functions)
     * [Boolean](#Boolean)
     * [BoOperators](#BoOperators)
     * [Conditionals](#Conditionals)
     * [Lists](#Lists)
     * [Tuples](#Tuples)
     * [Looping](#Looping)
     * [Modules](#Modules)
     * [Sockets](#Sockets)
     * [InputOutput](#InputOutput)
## Strings
```
#!/bin/python3

#Print string

print("Hello, world!") #comillas dobles
print('\n') #Nueva linea
print('Hello, world!')  #comillas simples
 
print("""This string runs
multiple lines!""") #triple comillas para multi-linea

print("This string is "+"awesome!")
```
## Math
```
#!/bin/python3

#Math
print(50 + 50) #add
print(50 - 50) #subtract
print(50 * 50) #multiply
print(50 / 50) #divide
print(50 + 50 - 50 * 50 / 50) #PEMDAS
print(50 ** 2) #exponentes
print(50 % 6) #modulo
print(50 // 6) #sin restos
```
## Variables
```
#!/bin/python3
#Variables y metodos
quote = "All is fair in love and war."
print(quote.upper()) #uppercase
print(quote.lower()) #lowercase
print(quote.title()) #titlecase

print(len(quote)) #cuantos caracteres contiene

name = "Kein" #string
age = 30 #int int(30)
gpa = 3.7 #float float(3.7)

print(int(age))
print(int(30.1))

print("My name is " + name + " and I am " + str(age) + " years old.")

age += 1
print(age)

birthday = 1
age += birthday
print(age)

print('\n')
```
## Functions
```
print("Here is an example function:")

def who_am_i(): #This is a function #Little program
	name = "Heath"
	age = 30
	print("My name is " + name + " and I am " + str(age) + " years old.")

who_am_i()

#adding parameters
def add_one_hundred(num):
	print(num + 100)
add_one_hundred(100)

#multiple parameters
def add(x,y):
	print(x + y)
add(7,7)

def multiply(x,y):
	return x * y
print (multiply(7,7))

def square_root(x):
	print(x ** .5)

square_root(64)

def new_line():
	print('\n')
new_line()
```
## Boolean
```
#!/bin/python3
print("Boolean expressions:")

bool1 = True
bool2 = 3*3 == 9
bool3 = False
bool4 = 3*3 != 9

print(bool1,bool2,bool3,bool4)
print(type(bool1))

bool5= "True"
print(type(bool5))
```
## BoOperators
```
#!/bin/python3
greater_than = 7 > 5
less_than = 5 < 7 
greater_than_equal_to = 7 >= 7
less_than_equal_to = 7 <= 7

test_and = (7 > 5) and (5 < 7) #True

test_and2 = (7 > 5) and (5 > 7) #False

test_or = (7 > 5) or (5 < 7) #True

test_or2 = (7 > 5) or (5 > 7) #True

test_not = not True #False

print(test_and)
```

## Truth Table

| A            | B             | A and B |
| ------------ | ------------- | ------- |
| True         | True          | True    |
| True         | False         | False   |
| False        | True          | False   | 
| False        | False         | False   |

## Conditionals
```
#!/bin/python3
def drink(money):
	if money >= 2:
		return "You've got yourself a drink!"
	else:
		return "No drink for you!"

print(drink(3))
print(drink(1))

def alcohol(age, money): 
	if (age >= 21) and (money >= 5):
		return "We're getting a drink!"
	elif (age >= 21) and (money < 5):
		return "Come back with more money."
	elif (age < 21) and (money >= 5):
		return "Nice try,kid!"
	else:
		return "You're too poor and too young"
print(alcohol(21,5))
print(alcohol(21,4))
print(alcohol(20,4))A
```
## Lists
```
#!/bin/python3
movies = ["Matrix", "Avatar", "The Hangover", "Harry Potter"]

print(movies[1]) #return the second item
print(movies[0]) #returns the first item on the list
print(movies[1:4])
print(movies[1:]) #grab all the items
print(movies[:2])
print(movies[-1]) #Last item

print(len(movies))
movies.append("JAWS")
print(movies)
movies.sort()
movies.pop() #Delete last item
print(movies)
movie.insert
movies.pop(0)
print(movies)
```
## Tuples
```
#!/bin/python3 
#cannot be change.
grades = ("a", "b", "c", "d", "f",)
print(grades[1])
```
## Looping
```
#!/bin/python3 
#For loops - start to finish of an iterate
vegetables = ["cucumber", "spinach", "cabbage"]
for x in vegetables:
	print(x)

#While loops - Execute as long as true

i = 1 

while i < 10: 
	print(i)
	i += 1
```
## Modules
```
#!/bin/python3
import sys #system functions and parameters
from datetime import datetime as dt #import with alias
print(dt.now())

my_name = "Neiro"
print(my_name[0])  #primera letra
print(my_name[-1]) #ultima letra

sentence = "This is a sentence."
print(sentence[:4])

print(sentence.split())

sentence_split = sentence.split()
sentence_join = ' '.join(sentence_split)
print(sentence_join)

quote = "He said, \"give me all your money\""
print(quote)

too_much_space = " 			hello 			"
print(too_much_space.strip())

print("A" in "Apple")
print("a" in "Apple")

letter = "A"
word = "Apple"
print(letter.lower() in word.lower()) #Improved

movie = "The Hangover"
print("My favorite movie is {}.".format(movie))

#Dictionaries - key/value pairs {}
drink = {"White Russian": 7, "Old fashion": 10, "Lemon Drop": 8} #drink is key, price is value
print(drink)

employees = {"Finance": ["Bob", "Linda", "Tina"], "IT": ["Gen", "Luis", "Teddy"], "HR": ["Jimmy", "Mort"]}
print(employees)

employees['Legal'] = ["Mr. Frond"] #add new key:value pair
print(employees)

employees.update({"Sales": ["Andie", "Ollie"]}) #add new key:value pair
print(employees)

drink['White Russian'] = 8
print(drink)

print(drink.get("White Russian"))
```
## Sockets
```
#!/bin/python3

import socket 

HOST = '127.0.0.1'
PORT = 10101

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #INET = IPV4  SOCK_STREAM = PORT
s.connect((HOST,PORT)) #just make a connection quick, but we can tell to send data etc.
```
## InputOutput
```
name=raw_input("What is your name?")
print "Hello, "+ name

a=5
b="Hello"
c=8.6
print "The valor of a is %d, the valor of b %s, and the valor of c is %f" % (a,b,c)

open ("example.txt","w") #open txt.
open ("example.txt","r") #Lectura
open ("example.txt","r+") #Lectura y escritura.
open ("example.txt","w+") #sobreescribir

arch.read() 
arch.readline()
arch.write()
arch.close() 
```
