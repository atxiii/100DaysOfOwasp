# BOM & DOM

## BOM:

- Browser Object Model
- Allows JavaScript to "talk to" the browser.
- Manage browser windows and enable communication between the windows
- There is no standard defined for BOM, hence different browsers implement it in different ways
- Each HTML page which is loaded into a browser window becomes a Document object and a document object is an object in the BOM.
- All global JavaScript objects, functions, and variables automatically become members of the window object.

BOM Methods:

- window
- screen
- location
- history
- navigator
- popup alert
- timing
- cookies

## DOM:

- Document Object Model
- It is a standard defined by W3C and is specific to current HTML document
- The HTML DOM document object is the owner of all other objects in your web page.
- DOM is a programming interface (API) for representing and interacting with HTML, XHTML and XML documents.
- Organizes the elements of the document in a tree structure (DOM tree) and in the DOM tree, all elements of the document are defined as objects (tree nodes) which have properties and methods.
- DOM ****tree objects can be accessed and manipulated with the help of any programming language
- DOM **is a subset of BOM

**DOM Methods:**

- document.getElementById(id)
- document.getElementsByTagName(name)
- document.getElementsByClassName(name)
- document.createElement(element)
- document.removeChild(element)

**Properties:**

- document.body
- document.cookie
- document.doctype
- document.documentElement
- document.documentMode
