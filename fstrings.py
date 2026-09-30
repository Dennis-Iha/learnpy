first = 'john'
last ='martin'
msg =f'{first} {last} is a baby' # dynamically insterting values in strings
print(len(msg)) #len calculate no of characters in string
print(msg)
print(msg.lower()) #lowercase
# .title capitalises the first letter of every word and the rest small letters
print(msg.upper()) #method  to convert to upper case
course = 'alphabets'
print(course.find('p')) #find the index position/start of a character(s)
print(course.replace('p', 'b')) #replace with another word
print('baby' in msg) #bool inpections in string