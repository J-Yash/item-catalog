Prerequisites:
    #Virtualbox and Vagrant VM(Not necessary but would save you from getting module dependancy errors :) )
    #If no Vagrant then,
        #Python 2.7
        #SQLite3 database module for python
        #Flask module
        #SeaSurf module

How to run this project?
    #Install all the above mentioned modules or Vagrant.
    #If you're running on Vagrant, use the Vagrant file provided. Use "vagrant up" and "vagrant ssh". then "cd /vagrant".
    #Run the command "python database_setup.py" (without quotation marks) in the cmd line window (make sure you are in the same directory in the cmd line window) to create the SQLite database
    #Run the command "python project.py" (without quotation marks) in the cmd line window (make sure you are in the same directory in the cmd line window) to run the project.
    # Go to localhost:8081/bakeries
    #Play around 
