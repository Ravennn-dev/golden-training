<?php

use Tests\TestCase;
use Illuminate\Http\Request;
use App\Repositories\UserRepository;
use App\Http\Controllers\UserController;
use Illuminate\Validation\ValidationException;

class UserControllerTest extends TestCase
{
    public function makeController($repository = null)
    {
        $repository ??= $this->createMock(UserRepository::class);

        return new UserController($repository);
    }

    public function test_apiRegister_RequestData_ValidationInvalidnException()
    {
        $this->expectException(ValidationException::class);

        $request = new Request([
            'name' => 'test',
            'username' => 'test-username',
        ]);

        $controller = $this->makeController();
        $controller->apiRegister($request);
    }

    public function test_apiRegister_mockRepository_getUserByUsername()
    {
         $request = new Request([
            'name' => 'test',
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->exactly(1))
            ->method('getUserByUsername')
            ->with('test-username')
            ->willReturn((object)['test']);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

    public function test_apiRegister_stubRepositorygetUserByUsernameHasData_responseUsernameAlreadyTaken()
    {
        $expected = response()->json([
                'message' => 'Username already taken'
            ], 409);

        $request = new Request([
            'name' => 'test',
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn((object)['test']);

        $controller = $this->makeController($stubRepository);
        $result = $controller->apiRegister($request);

        $this->assertEquals($expected, $result);
    }

    public function test_apiRegister_mockRepositorygetUserByUsernameNullData_createUser()
    {
        $request = new Request([
            'name' => 'test',
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->exactly(1))
            ->method('createUser')
            ->with('test', 'test-username', 'test-password')
            ->willReturn((object)[
                'name' => 'name',
                'username' => 'username'
            ]);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

     public function test_apiRegister_stubRepositorygetUserByUsernameNullData_responseRegisterSuccess()
    {
        $expected = response()->json([
            'message' => 'User Registered Successfully',
            'user' => [
                'name' => 'name',
                'username' => 'username'
            ]
        ], 201);

        $request = new Request([
            'name' => 'test',
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

         $stubRepository->method('createUser')
            ->willReturn((object)[
                'name' => 'name',
                'username' => 'username'
            ]);

        $controller = $this->makeController($stubRepository);
        $result = $controller->apiRegister($request);

        $this->assertEquals($expected, $result);
    }

    public function test_apiLogin_invalidRequestData_ValidationException()
    {
        $this->expectException(ValidationException::class);

        $request = new Request([
            'password' => 'test-password',
        ]);

        $controller = $this->makeController();
        $controller->apiLogin($request);
    }

    public function test_apiLogin_mockRepository_getUserByUsernamePassword()
    {
         $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->exactly(1))
            ->method('getUserByUsernamePassword')
            ->with('test-username', 'test-password')
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_stubRepositorygetUserByUsernamePasswordNullData_responseInvalidCredentials()
    {
        $expected = response()->json([
            'success' => false,
            'message' => 'Invalid credentials'
        ], 401);

        $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsernamePassword')
            ->willReturn(null);

        $controller = new UserController($stubRepository);
        
        $result = $controller->apiLogin($request);

        $this->assertEquals($expected->getStatusCode(), $result->getStatusCode());
        $this->assertEquals($expected->getData(), $result->getData());
    }

    public function test_apiLogin_mockRepositorygetUserByUsernamePassword_assignApiTokenToUser()
    {
        $mockUser = new stdClass();
        $mockUser->id = 1;
        $mockUser->name = 'test';
        $mockUser->username = 'test-username';

        $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        
        $mockRepository->expects($this->once())
            ->method('assignApiTokenToUser')
            ->with(1)
            ->willReturn('generated-token');

        $mockRepository->method('getUserByUsernamePassword')
            ->willReturn($mockUser);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('generated-token', $response->getData(true)['api_token']);
    }

    public function test_apiLogin_mockRepositorygetuserByUsernamePassword_responseLoginSuccess()
    {
        $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $mockUser = new stdClass();
        $mockUser->id = 1;
        $mockUser->name = 'test';
        $mockUser->username = 'test-username';

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('getUserByUsernamePassword')
            ->with('test-username', 'test-password')
            ->willReturn($mockUser);

        $mockRepository->expects($this->once())
            ->method('assignApiTokenToUser')
            ->with(1) 
            ->willReturn('generated-token');

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals(200, $response->getStatusCode());
        
        $responseData = $response->getData(true);
        $this->assertTrue($responseData['success']);
        $this->assertEquals('Login successful', $responseData['message']);
        $this->assertEquals('generated-token', $responseData['api_token']);
        $this->assertEquals([
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ], $responseData['user']);
    }

    public function test_apiGetAuthenticatedUser_invalidToken_responseUnauthorized()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/user',
            'GET',
            [], [], [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->with($token)
            ->willReturn(null); // Token is invalid

        $controller = $this->makeController($stubRepository);

        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals(401, $response->status());
        $this->assertEquals([
            'message' => 'Unauthorized'
        ], $response->getData(true));
    }

    public function test_apiGetAuthenticatedUser_validToken_returnsUserData()
    {
        $token = 'valid-token';

        $request = Request::create(
            '/api/user',
            'GET',
            [], [], [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $expectedUser = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->with($token)
            ->willReturn($expectedUser);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals(200, $response->status());
        $this->assertEquals([
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ], $response->getData(true));
    }

    public function test_apiLogout_mockRepository_authenticateToken_invalidToken_bearerTokenPassedToauthenticateToken()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/logout',
            'GET',
            [], [], [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null); 

        $controller = $this->makeController($mockRepository);
        $controller->apiLogout($request);
    }


    public function test_apiLogout_mockRepository_authenticateToken_userExists_callsClearApiToken()
    {
        $token = 'valid-token';

        $request = Request::create(
            '/api/logout',
            'POST',
            [], [], [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $user = (object)['id' => 1];

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn($user);

        $mockRepository->expects($this->once())
            ->method('clearApiToken')
            ->with($user->id);

        $controller = $this->makeController($mockRepository);

        $controller->apiLogout($request);
    }

    public function test_apiLogout_mockRepository_authenticateTokenUserNull_doesNotCallClearApiToken()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/logout',
            'POST',
            [], [], [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $mockRepository->expects($this->never())
            ->method('clearApiToken');

        $controller = $this->makeController($mockRepository);

        $controller->apiLogout($request);
    }

    public function test_apiDeleteUser_invalidRequestdata_validateException()
    {
        $this->expectException(ValidationException::class);

        $request = new Request([]);

        $controller = $this->makeController();
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_mockRepository_getUserByUsername()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('test-username')
            ->willReturn((object)[
                'id' => 1, 'username' => 'test-username'
            ]);

        $mockRepository->method('deleteUser')
            ->willReturn(true);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_mockRepository_getUserByUsernameNullData()
    {
        $expected = response()->json([
            'success' => false,
            'message' => 'User not found.'
        ], 404);

        $request = new Request([
            'username' => 'test-username',
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $controller = new UserController($stubRepository);
        
        $result = $controller->apiDeleteUser($request);

        $this->assertEquals($expected->getData(), $result->getData());
    }

    public function test_apiDeleteUser_mockRepository_deleteUserCalledWhenUserExists()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $user = (object)[
            'id' => 1,
            'username' => 'test-username',
        ];

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('test-username')
            ->willReturn($user);

        $mockRepository->expects($this->once())
            ->method('deleteUser')
            ->with($user->id)
            ->willReturn(true);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_mockRepository_responseSuccessDeletion()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $user = (object)[
            'id' => 1,
            'username' => 'test-username',
        ];

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('getUserByUsername')
            ->willReturn($user);

        $mockRepository->method('deleteUser')
            ->willReturn(true);

        $controller = $this->makeController($mockRepository);

        $response = $controller->apiDeleteUser($request);

        $this->assertEquals([
            'success' => true,
            'message' => 'Profile deleted successfully.',
        ], $response->getData(true));
    }

    public function test_apiUpdate_mockRepository_authenticateToken_invalidToken()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/update',
            'GET',
            [], [], [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null); 

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_mockRepository_authenticateTokenInvalidToken_responseUnauthorized()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/update',
            'GET',
            [], [], [], 
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals([
            'message' => 'Unauthorized'
        ], $response->getData(true));
    }

    public function test_apiUpdate_RequestData_ValidationException()
    {
        $token = 'valid-token';

        $request = Request::create(
            '/api/update',
            'POST',
            [
                'password' => '', 
            ],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
            ]
        );

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->with($token)
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'testuser',
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_checkUsernameAvailable()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1, 
            'name' => 'test', 
            'username' => 'test-username'
        ];

        $request = Request::create(
            '/api/update',
            'POST',
            [
                'username' => 'new-username'
            ],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
        ]);

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->with('new-username')
            ->willReturn(null); 

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }

    public function test_apiUpdate_checkUsernameAlreadyTaken()
    {
        $token = 'valid-token';
        $currentUser = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $otherUser = (object)[
            'id' => 2,
            'name' => 'other',
            'username' => 'taken-username'
        ];

        $request = Request::create(
            '/api/update',
            'POST',
            [
                'username' => 'taken-username'
            ],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        
        $mockRepository->method('authenticateToken')
            ->willReturn($currentUser);

        $mockRepository->method('getUserByUsername')
            ->with('taken-username')
            ->willReturn($otherUser);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(422, $response->status());
        $this->assertEquals(
            ['error' => 'Username already taken.'],
            json_decode($response->content(), true)
        );
    }

    public function test_apiUpdate_updatesNameOnly()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];
        
        $request = Request::create(
            '/api/update',
            'POST',
            ['name' => 'new-test-name'],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);
        
        $mockRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['name' => 'new-test-name']);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }

    public function test_apiUpdate_updatesUsernameOnly()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];
        
        $request = Request::create(
            '/api/update',
            'POST',
            ['username' => 'new-test-username'],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);
        
        $mockRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['username' => 'new-test-username']);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }

    public function test_apiUpdate_updatesPasswordOnly()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];
        
        $request = Request::create(
            '/api/update',
            'POST',
            ['password' => 'new-password'],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);
        $mockRepository->method('getUserByUsername')
            ->willReturn(null);
        
        $mockRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['password' => md5('new-password')]);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }

    public function test_apiUpdate_updatesMultipleFields()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'old-name',
            'username' => 'old-username'
        ];
        
        $request = Request::create(
            '/api/update',
            'POST',
            [
                'name' => 'new-name',
                'username' => 'new-username',
                'password' => 'new-password'
            ],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);
        
        $mockRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, [
                'name' => 'new-name',
                'username' => 'new-username',
                'password' => md5('new-password')
            ]);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }

    public function test_apiUpdate_ignoresEmptyPassword()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];
        
        $request = Request::create(
            '/api/update',
            'POST',
            ['password' => ''],
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);
        
        $mockRepository->expects($this->never())
            ->method('updateUser');

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }
    
    public function test_apiUpdate_doesNothingWhenNoFieldsToUpdate()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];
        
        $request = Request::create(
            '/api/update',
            'POST',
            [], // No update data
            [], [], [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);
        
        $mockRepository->expects($this->never())
            ->method('updateUser');

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals(200, $response->status());
    }

}