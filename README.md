# Primitive-Hospital-Record-Management-Application
A Hospital Record Management System where medical records can be stored and viewed safely


This project uses NodeJS, ExpressJS, MongoDB as the architecture for building the application.

The project encompasses the basics of CyberSecurity like Hashing with Salt, Encryption/Decryption, Encoding/Decoding, 2-Factor Authentication, Authorization of different users based on their role.

The Authorization rules:
  Doctors can create new medical records for patients and view any past medical records.
  Nurses cannot create new medical records, but can view any past medical records.
  Patients cannot create new medical records and cannot view any past medical records, but they can view their medical record.


To run the code, 
  1) Open a terminal, and type <b>npm init -y</b>

     <img width="133" height="34" alt="image" src="https://github.com/user-attachments/assets/1eeba006-75c3-4058-ad1c-8c96ce9d26c5" />

  3) Then type the required libraries (express, mongoose, bcrypt, crypto, nodemailer, dotenv, jsonwebtoken) using the <b>npm install [LIBRARY_1], [LIBRARY_2], ...</b>

     <img width="875" height="42" alt="image" src="https://github.com/user-attachments/assets/716d8f29-1337-45fc-bd15-390272cd6e93" />

  4) (OPTIONAL) Can install nodemon library as a development dependency using <b>npm install nodemon --save-dev</b>

     <img width="339" height="37" alt="image" src="https://github.com/user-attachments/assets/08a79a4f-8521-4813-a14d-67893a81825e" />

  5) Create the file <b>.env</b> in root folder.
  6) Add the following to the <b>.env</b> file,
     
     <img width="617" height="86" alt="image" src="https://github.com/user-attachments/assets/845e2bd3-9155-42e5-9355-73182d3ffafc" />

  7) In the <b>PORT</b> field, type the port in which you want to run the server in (eg: 3000, 7001, ...)
  8) In the <b>JWT_SECRET</b> field, type the secret key you have for digitally signing and verifying JSON Web Tokens (JWTs).
  9) Create a MongoDB deployment (either using MongoDB Atlas app or MongoDB online)
  10) Set the password for the database user.
  11) Get the connection string for the database.
  12) Fill that connection string in the <b>CONNECTION_STRING</b> field of the <b>.env</b> file.
      The connection string looks something like this, 

      <img width="1483" height="73" alt="image" src="https://github.com/user-attachments/assets/123e6ad8-d037-4328-ae8c-7ff137a1dfbe" />

  13) If you have installed nodemon, in the <b>package.json</b> file, in the scripts field add <b>"dev": "nodemon src/server.js"</b>, you can use any string in the place of <b>"dev"</b>
  
      <img width="663" height="124" alt="image" src="https://github.com/user-attachments/assets/2d2db8b2-5250-4690-9e21-5566915bb6b0" />

  14) Now type <b>npm run dev</b> in the terminal to run the server.

      <img width="141" height="28" alt="image" src="https://github.com/user-attachments/assets/4c9e0cea-6b58-482a-acc7-abea7dda7098" />

  16) Now open a web browser and type URL <b>localhost:[PORT_NUMBER]/register.html</b> , the port in which your server is runnning.
