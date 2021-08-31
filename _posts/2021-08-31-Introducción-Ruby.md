---
layout: single
title: Introducción Ruby
excerpt: "Ruby es un lenguaje de programación interpretado, reflexivo y orientado a objetos, creado por el programador japonés Yukihiro "Matz" Matsumoto, quien comenzó a trabajar en Ruby en 1993, y lo presentó públicamente en 1995".
date: 2021-08-31
classes: wide
categories:
  - Blue Team
  - Red Team
  - infosec
tags:
  - Blue Team
  - Red Team


---


## Start
```
gem list #List all gems
gem search #search for gems
gem install <gem>
irb # Work command line
gem install pry
pry --simple-prompt
```
## Math
```
puts 4 * 10
puts 5 - 12
puts 30 / 40
"Jimmy" * 5
40.to_s.reverse
```
## Convert
```
to_s converts things to strings
to_i converts things to integers (numbers)
to_a converts things to arrays
```
## Arrays_Lists_Variables
```
[]
[12, 47, 35, 32]
[12, 47, 35, 32].max #highest number.
ticket = [12, 47, 35] #Save it inside ticket.
ticket.sort! #Sort list.
poem.gsub("toast", "honeydew") #Sustituir algo de una variable.
poem.lines.reverse # Turn into a list, 
puts poem.lines.reverse.join
poem.downcase
poem.swapcase
"Jimmy".reverse #Backwards
```
## Functions
```
def cuadrado(x)
	return x**2
end

cuadrado(9)

a["curso"]="ALC"
a["valor"]="10"

def curso(hash)
	puts hash["curso"]
	puts hash["valor"]
end
curso(a)
```
## Methods
Un método en Ruby es también conocido como una función, los métodos tienen un conjunto de instrucciones que quieres que se ejecuten en un momento determinado.
```
def tame( number_of_shrews )
  number_of_shrews.times {
    puts "Tamed a shrew"
  }
------------------------------
def output_something(value)
  puts value 
end
------------------------------
def calculate_value(x,y)
  x + y
end
------------------------------
s = get_shakey #Transform json to ruby hash
------------------------------
def print_plays(year_from, year_to)
  get_shakey["William Shakespeare"]
    .select { |k, v|
      year_from <= v["finished"] &&
      year_to   >= v["finished"]
    }.each { |k, v|
      puts "#{v["title"].ljust(30)} #{v["finished"]}"
    }
end
print_plays(1600, 1605)
```
## Hash
* A hash is like an array, only every one of its elements has a name.
* Keep in mind that hashes won’t keep things in order. That’s not their job. It’ll just pair up two things: a key and a value.
* You can also try this with .values instead of .keys.
```
Hash.new
books.keys
hashes_example={'nombre'=>'chee', 'valor'=>'10'}
hashes_example.class
hashes_example.class.superclass
hashes_example.keys
hashes_example.values
hashes_example.lenght
hashes_example['validez']='2 años' #introducir un dato más
```
## Blocks
```
5.times { print "Odelay! " }

5.times { |time|
  puts time
}
```
## Condicionales
```
#!/usr/bin/ruby
if 1 < 2
  puts "It is true: 1 is less than 2"
end
```
```
#!/usr/bin/ruby
nota=4.8

if nota > 7
        puts "#{nota} es mayor que un simple aprobado"
elsif nota == 2.3
        puts "#{nota} es un suspenso"
else
        puts "#{nota} a saber qué ha sacado..."
end

if nota > 4.5 and nota < 5.5
        puts "#{nota}...uuuuuufffffff .. aprobado por los pelos!!"
end

nota=7

case nota
when 3.5 .. 4.5
        puts "SUSPENSO"
when 4.5 .. 5
        puts "APROBADO"
when 7 .. 9
        puts "NOTABLE"
when 9 .. 10
        puts "pro"
else
        puts "xD else función"
end
```
![image](https://user-images.githubusercontent.com/64669644/89028988-b0b71900-d32d-11ea-800f-bae789c6fce6.png)
## Loops
```
#!/usr/bin/ruby

nota=0

while nota <5 do
        puts("Suspenso")
        nota=nota +1
end

nota2=0
begin
        puts("mientras #{nota} sea menos que 5..estas SUSPENDIDO!!!!")
        nota2 +=1
end while nota2 < 5

for nota3 in 5..10
        puts "la nota #{nota} significa que estas aprobado!!!!"
end
```
## Directories_Files
```
Dir.pwd 
Dir.mkdir
Dir.chdir("example") #Entrar dentro
Dir.chdir("/root")
Dir.entries(".") #ls

File.exists? "info2.txt"
File.directory? "example"
File.ftype "example"

File.readable? "info2.txt" 
File.writable?
File.executable?

creacion=File.ctime "info2.txt"
modificacion=File.mtime "info2.txt"
visualizado=File.atime "info2.txt"


File.new("example.txt", "w")
File.open("example.txt", "r") do  |file|
|      contador = file.read
|      puts contador
end 

File.new("example.TXT", "w")
File.open("example.TXT", "r") do  |file|
|      file.puts "Este archivo xd"
|      file.puts "jeje"
end 
```
## Sockets
```
requiere 'socket'

socket=TCPSocket.open("<ip>",5555)
socket.addr
socket.peeraddr
```
## ListarIP's
```
#!/usr/bin/ruby
(ARGV[1]..ARGV[2]).each {|ip| print ARGV[0], ".", ip,"\n"}
```
## Expresiones y extraer información.
```
"Ruby parece mas interesante que python jeje xD"
=~/\d/ #numero de caracteres
=~/\D/ #null
=~/\s/ #Los primeros 9 caracteres
=~/\S/ #Sin espacio
=~/\w/ 
=~/\W/ 
/(paco){3}/

ip=/(\d{1,3}).(\d{1,3})/.(\d{1,3}).(\d{1,3})/
valor=ip.match("192.168.126.1")


texto="la siguiente ip 192.168.126.131 esta por encima de la ip 192.168.126.2"
creacion_ip=/(?:((\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})))/
resultado=text.match(creacion_ip)
resultado=texto.scan(creacion_ip)

(?:\d{1,3}\.){3}.(\d{1,3})
```
## Servidor
```
#!/usr/share/ruby

require 'socket'

def main(ip,port)
        server = TCPServer.new ip,port
        loop do
                Thread.start(server.accept) do |client|
                        print Time.new.to_s + " - IP: "+client.peeraddr[3]
                        print " Port: "+client.peeraddr[1].to_s+"\n"
                        case client.gets.chop
                                when "Hola" then client.puts("Hola amigo y bienvenido")
                                when "Adios" then client.puts("Vale...adios xD")
                                else client.puts("error")
                        end
                        client.close
                end
        end
end

begin
        ip = ARGV[0]
        port = ARGV[1]
        main(ip,port)
rescue Exception => e
         puts e
end


```
## Cliente
```
#!/usr/bin/ruby

require 'socket'

def main(host,port,mesg)
        TCPSocket.open(host,port) do |soc|
                soc.puts(mesg)
                puts soc.gets
        end
end

begin
        host = ARGV[0]
        port = ARGV[1]
        type = ARGV[2]
        main(host,port,type)
rescue Exception => e
        puts s
end

```
