# Book_SearchEngine

## Table of Content 📖
  - [Description](#description)
  - [User Story](#user-story)
  - [Acceptance Criteria](#acceptance-criteria)
  - [Installation](#installation)
  - [Results](#results)
  - [Reach-me](#reach-me)
  - [GitHub-name](#github-name)
  - [App-Link](#app-link)

## Description

This is a application that refactors a Google Books API search engine from a RESTful API to a GraphQL API with Apollo Server. The search engine is built using the MERN stack - MongoDB, Express.js, React, and Node.js. A user can create an account, search for books, and save them to a list. On a separately rendered page, the user can see their saved books and remove books from the list.

## User Story

```md
AS AN avid reader
I WANT to search for new books to read
SO THAT I can keep a list of books to purchase
```


## Acceptance Criteria

```md
GIVEN a book search engine
WHEN I load the search engine
THEN I am presented with a menu with the options Search for Books and Login/Signup and an input field to search for books and a submit button
WHEN I click on the Search for Books menu option
THEN I am presented with an input field to search for books and a submit button
WHEN I am not logged in and enter a search term in the input field and click the submit button
THEN I am presented with several search results, each featuring a book’s title, author, description, image, and a link to that book on the Google Books site
WHEN I click on the Login/Signup menu option
THEN a modal appears on the screen with a toggle between the option to log in or sign up
WHEN the toggle is set to Signup
THEN I am presented with three inputs for a username, an email address, and a password, and a signup button
WHEN the toggle is set to Login
THEN I am presented with two inputs for an email address and a password and login button
WHEN I enter a valid email address and create a password and click on the signup button
THEN my user account is created and I am logged in to the site
WHEN I enter my account’s email address and password and click on the login button
THEN I the modal closes and I am logged in to the site
WHEN I am logged in to the site
THEN the menu options change to Search for Books, an option to see my saved books, and Logout
WHEN I am logged in and enter a search term in the input field and click the submit button
THEN I am presented with several search results, each featuring a book’s title, author, description, image, and a link to that book on the Google Books site and a button to save a book to my account
WHEN I click on the Save button on a book
THEN that book’s information is saved to my account
WHEN I click on the option to see my saved books
THEN I am presented with all of the books I have saved to my account, each featuring the book’s title, author, description, image, and a link to that book on the Google Books site and a button to remove a book from my account
WHEN I click on the Remove button on a book
THEN that book is deleted from my saved books list
WHEN I click on the Logout button
THEN I am logged out of the site and presented with a menu with the options Search for Books and Login/Signup and an input field to search for books and a submit button  
```

## Installation:

- Download it through Github
- Run npm i in terminal to install packages
- Running npm run develop will give you access to the Apollo Server (Graph QL) and the localhost webpage

## Results:

![Animation shows "Harry Potter" typed into a search box and books about Harry Potter appearing as results.](./Assets/HarryPotter.gif)
![Animation shows "Percy Jackson" typed into a search box and books about Percy Jackson appearing as results.](./Assets/PercyJacksonbooks.gif)

## Reach-me

jessyjosephine.mscit@gmail.com

## GitHub-name

https://github.com/Jessyjdi/Book_SearchEngine

## App-Link

https://dry-woodland-46365.herokuapp.com/
