# Primitive-Hospital-Record-Management-Application
A Hospital Record Management System where medical records can be stored and viewed safely


This project uses NodeJS, ExpressJS, MongoDB as the architecture for building the application.

The project encompasses the basics of CyberSecurity like Hashing with Salt, Encryption/Decryption, Encoding/Decoding, 2-Factor Authentication, Authorization of different users based on their role.

The Access Control rules:
  Doctors can create new medical records for patients and view any past medical records.
  Nurses cannot create new medical records, but can view any past medical records.
  Patients cannot create new medical records and cannot view any past medical records, but they can view their medical record.


To run the code, 
  1) Open a terminal, and type <b>npm init -y</b>


  3) Then type the required libraries (express, mongoose, bcrypt, crypto, nodemailer, dotenv, jsonwebtoken) using the <b>npm install [LIBRARY_1], [LIBRARY_2], ...</b>


  4) (OPTIONAL) Can install nodemon library as a development dependency using <b>npm install nodemon --save-dev</b>


  5) Create the file <b>.env</b> in root folder.
  6) Add the following to the <b>.env</b> file,
  7) In the <b>PORT</b> field, type the port in which you want to run the server in (eg: 3000, 7001, ...)
  8) In the <b>JWT_SECRET</b> field, type the secret key you have for digitally signing and verifying JSON Web Tokens (JWTs).
  9) Create a MongoDB deployment (either using MongoDB Atlas app or MongoDB online)
  10) Set the password for the database user.
  11) Get the connection string for the database.
  12) Fill that connection string in the <b>CONNECTION_STRING</b> field of the <b>.env</b> file.
      The connection string looks something like this, 


  13) If you have installed nodemon, in the <b>package.json</b> file, in the scripts field add <b>"dev": "nodemon src/server.js"</b>, you can use any string in the place of <b>"dev"</b>

  14) Now type <b>npm run dev</b> in the terminal to run the server.


  16) Now open a web browser and type URL <b>localhost:[PORT_NUMBER]/register.html</b> , the port in which your server is runnning.
