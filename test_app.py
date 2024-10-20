import json
import unittest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from unittest import mock
from main import app, get_books_from_mongo, get_user, pwdVerify,  authenticate_user,  shutdown_db_client
from bson import ObjectId
import time

@patch('main.client')
class TestUser(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        with mock.patch('main.MongoClient.close') as mock_close:
            mock_close.return_value = None

    def test_login_success(self, mock_mongo):
        mock_user_collection = mock_mongo.return_value['library']['Users']
        mock_user_collection.find_one.return_value = {"username": "testuser",
                                                      "hashed_pwd": "$2b$12$OiDLezi69suuaLVemOSWPuRtKuU/Fwu3mX2OliVqCUVRSLnIgKFiC"}



        response = self.client.post("/token", data={"username": "testuser", "password": "123"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())


    @patch('main.authenticate_user')
    def test_login_fail(self, mock_authenticate, mock_mongo):
        mock_user_collection = mock_mongo.return_value['library']['Users']
        mock_user_collection.find_one.return_value = {"username": "testuser",
                                                      "hashed_pwd": "$2b$12$OiDLezi69suuaLVemOSWPuRtKuU/Fwu3mX2OliVqCUVRSLnIgKFiC"}

        mock_authenticate.return_value =None


        response = self.client.post("/token", data={"username": "testuser", "password": "123"})

        self.assertEqual(response.status_code, 401)




    def test_register(self, mock_mongo):
        mock_user_collection = mock_mongo.return_value['library']['Users']
        mock_user_collection.find_one.return_value = None
        mock_user_collection.insert_one.return_value = mock.Mock(inserted_id=ObjectId())


        response = self.client.post("/register", json={"username": "tetfuffser", "password": "123"})


        self.assertEqual(response.json(), {'detail': 'Error username already exists'})




@patch("main.jwt.decode", return_value={"sub": "testuser"})
@patch("main.get_current_user", return_value={"username": "testuser"})
@patch('main.redis_client')  # Ensure this path is correct
@patch('main.collection')
class TestGetBooks(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        with mock.patch('main.MongoClient.close') as mock_close:
            mock_close.return_value = None

    def test_get_books(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        mock_collection.find.return_value = [{"_id": ObjectId(), "name": "b1", "status": True} ,
                                             {"_id": ObjectId(), "name": "b2", "status": True}
        ]
        mock_redis_client.get.return_value = None
        response = self.client.get("/books", headers={"Authorization":"Bearer dummy_token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 2)

    def test_cached_books(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        mock_collection.find.return_value = [{"_id": ObjectId(), "name": "b1", "status": True},
                                             {"_id": ObjectId(), "name": "b2", "status": True}
                                             ]
        mock_redis_client.get.return_value = None

        start_time = time.time()  # Start timer for first request
        response = self.client.get("/books", headers={"Authorization": "Bearer dummy_token"})
        end_time = time.time()  # End timer for first request

        print(f"First request time: {end_time - start_time:.4f} seconds")

        self.assertEqual(response.status_code, 200)


        mock_redis_client.setex.assert_called_once_with('books_cache',mock.ANY, mock.ANY)

        mock_redis_client.get.return_value = json.dumps([{"_id": str(ObjectId()), "name": "b1", "status": True},
                                             {"_id": str(ObjectId()), "name": "b2", "status": True}
                                             ])

        start_time = time.time()  # Start timer for second request
        response = self.client.get("/books", headers={"Authorization": "Bearer dummy_token"})
        end_time = time.time()  # End timer for second request

        print(f"Second request time: {end_time - start_time:.4f} seconds")
        self.assertEqual(response.status_code, 200)


@patch("main.jwt.decode", return_value={"sub": "testuser"})
@patch("main.get_current_user", return_value={"username": "testuser"})
@patch('main.redis_client')  # Ensure this path is correct
@patch('main.collection')
class TestGetOneBook(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        with mock.patch('main.MongoClient.close') as mock_close:
            mock_close.return_value = None


    def test_get_one_book(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id = "605c72f7f12b4f8e78fabe0b"
        db_book = {
            '_id': ObjectId(book_id),
            "name": "b1",
            "status": True
        }

        # Set the return value of the MongoClient to return our mocked collection
        mock_collection.find_one.return_value = db_book

        # Mock Redis to return None (so the code will query MongoDB)
        mock_redis_client.get.return_value = None

        response = self.client.get(f"/books/{book_id}", headers={"Authorization": "Bearer dummy_token"})
        print(response)

        # # Print statements for debugging
        print("Response Status Code:", response.status_code)
        print("Response JSON:", response.json())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["name"], "b1")
        self.assertEqual(type(response.json()["data"]["_id"]), str)
        self.assertEqual(response.json()["data"]["_id"], book_id)




    def test_Notfoundbook(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id = ObjectId()
        mock_collection.find_one.return_value = None
        mock_redis_client.get.return_value = None

        response = self.client.get(f"/books/{str(book_id)}", headers={"Authorization": "Bearer dummy_token"})
        print("Response Status Code:", response.status_code)
        print("Response JSON:", response.json())


        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"],"Book not found")

    def test_cache_book(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id = "605c72f7f12b4f8e78fabe0b"
        db_book = {
            '_id': ObjectId(book_id),
            "name": "b1",
            "status": True
        }
        mock_collection.find_one.return_value = db_book
        mock_redis_client.get.return_value = None

        start_time = time.time()
        response = self.client.get(f"/books/{book_id}", headers={"Authorization": "Bearer dummy_token"})
        end_time = time.time()
        print(f"First request time: {end_time - start_time:.4f} seconds")
        self.assertEqual(response.status_code, 200)

        mock_redis_client.setex.assert_called_once_with(f'book_{book_id}',mock.ANY,mock.ANY)

        mock_redis_client.get.return_value= json.dumps({
            '_id': book_id,
            "name": "b1",
            "status": True
        })
        start_time = time.time()
        response = self.client.get(f"/books/{book_id}", headers={"Authorization": "Bearer dummy_token"})
        end_time = time.time()
        print(f"Second request time: {end_time - start_time:.4f} seconds")
        self.assertEqual(response.status_code, 200)




@patch("main.jwt.decode", return_value={"sub": "testuser"})
@patch("main.get_current_user", return_value={"username": "testuser"})
@patch('main.redis_client')
@patch('main.collection')
class TestAddBook(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        with mock.patch('main.MongoClient.close') as mock_close:
            mock_close.return_value = None


    def test_add_book(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        mock_redis_client.get.return_value = None
        mock_id = ObjectId()
        mock_collection.insert_one.return_value = MagicMock(inserted_id=mock_id)

        response = self.client.post("/books/add", json={"name":"new book"}, headers={"Authorization": "Bearer dummy_token"})

        print("Response Status Code:", response.status_code)
        print("Response JSON:", response.json())

        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()["data"]["name"],"new book")

@patch("main.jwt.decode", return_value={"sub": "testuser"})
@patch("main.get_current_user", return_value={"username": "testuser"})
@patch('main.redis_client')  # Ensure this path is correct
@patch('main.collection')
class TestDeleteBook(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        with mock.patch('main.MongoClient.close') as mock_close:
            mock_close.return_value = None

    def test_delete_book(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id= ObjectId()
        mock_redis_client.get.return_value = None
        mock_collection.delete_one.return_value = mock.Mock(deleted_count=1)

        response = self.client.delete(f"books/delete/{str(book_id)}",headers={"Authorization": "Bearer dummy_token"})

        print("Response Status Code:", response.status_code)
        print("Response JSON:", response.json())
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['data'],{"message": "Book deleted successfully"})



@patch("main.jwt.decode", return_value={"sub": "testuser"})
@patch("main.get_current_user", return_value={"username": "testuser"})
@patch('main.redis_client')  # Ensure this path is correct
@patch('main.collection')
class TestUpdateBook(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        with mock.patch('main.MongoClient.close') as mock_close:
            mock_close.return_value = None

    def test_update1(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id = ObjectId()
        mock_redis_client.get.return_value = None
        mock_collection.update_one.return_value = mock.Mock(matched_count=1, modified_count=1)

        response= self.client.patch(f"/books/status/{str(book_id)}", headers={"Authorization": "Bearer dummy_token"})

        self.assertEqual(response.json()['data'],{"message": "Book's status successfully updated"})


    def test_update2(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id = str(ObjectId())
        mock_redis_client.get.return_value = None
        mock_collection.update_one.return_value = mock.Mock(matched_count=0)

        response= self.client.patch(f"/books/status/{book_id}", headers={"Authorization": "Bearer dummy_token"})


        self.assertEqual(response.status_code,404)
        self.assertEqual(response.json()['detail'],"Book not found")


    def test_update3(self, mock_collection, mock_redis_client, mock_get_current_user, mock_jwt_decode):
        book_id = str(ObjectId())
        mock_redis_client.get.return_value = None
        mock_collection.update_one.return_value = mock.Mock(matched_count=1, modified_count=0)

        response= self.client.patch(f"/books/status/{book_id}", headers={"Authorization": "Bearer dummy_token"})
        print("Response Status Code:", response.status_code)
        print("Response JSON:", response.json())

        self.assertEqual(response.json()['data'], {'message': "Book's status is already False"})


class TestGetBooksMongo(unittest.TestCase):

     @patch('main.collection')
     def test_get(self,mock_collection):
         mock_collection.find.return_value=[{"_id": ObjectId(), "name": "b1", "status": True} ,
                                             {"_id": ObjectId(), "name": "b2", "status": True}
        ]
         books = get_books_from_mongo()
         print(books)

         self.assertEqual(books[0]['name'],'b1')
         self.assertEqual(books[1]['name'],'b2')


@patch('main.user_collection')
class TestGetUser(unittest.TestCase):


    def test_get_user(self,mock_user_collection):
        mock_user_collection.find_one.return_value = {"username": "testing"}
        user = get_user("testing")

        self.assertEqual(user["username"],"testing")

    def test_user_not_found(self,mock_user_collection):
        mock_user_collection.find_one.return_value = None
        user= get_user("username")
        self.assertIsNone(user)



class test_pwd(unittest.TestCase):

    def test_pwd(self):
        plain_pwd= "123"
        hashed_pwd= "$2b$12$OiDLezi69suuaLVemOSWPuRtKuU/Fwu3mX2OliVqCUVRSLnIgKFiC"

        result = pwdVerify(plain_pwd,hashed_pwd)

        self.assertTrue(result)

class test_auth_user(unittest.TestCase):

    @patch('main.get_user')
    def test_user_exist(self,mock_get_user):
        mock_get_user.return_value = {
            "username":"testuser" ,
            "hashed_pwd":"$2b$12$OiDLezi69suuaLVemOSWPuRtKuU/Fwu3mX2OliVqCUVRSLnIgKFiC"
        }


        user = authenticate_user("testuser","123")
        print(user)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"],"testuser")


    @patch('main.get_user')
    def test_invalid_user(self, mock_get_user):
        mock_get_user.return_value = {
            "username": "testuser",
            "hashed_pwd": "$2b$12$OiDLezi96suuaLVemOSWPuRtKuU/Fwu3mX2OliVqCUVRSLnIgKFiC"
        }

        user = authenticate_user("testuser", "123")

        self.assertIsNone(user)

    @patch('main.get_user')
    def test_no_user_exist(self, mock_get_user):
        mock_get_user.return_value = None

        user = authenticate_user("testuser", "123")

        self.assertIsNone(user)






class test_shutdown(unittest.TestCase):

    @patch('main.client')
    @patch('main.redis_client')
    def test_shutdown_db_client(self, mock_redis_client, mock_mongo_client):
        with TestClient(app) as client:
            app.add_event_handler('shutdown',shutdown_db_client)
            shutdown_db_client()
            mock_mongo_client.close.assert_called_once()
            mock_redis_client.close.assert_called_once()









if __name__ == '__main__':
    unittest.main()