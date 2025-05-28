<?php

namespace Tests\Unit;

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

    public function test_apiLogin_invalidRequestData_ValidationInvalidException()
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

    public function test_apiLogin_stubRepositorygetUserByUsernamePasswordHasNoData_responseInvalidCredentials()
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

        $controller = $this->makeController($stubRepository);
        $result = $controller->apiLogin($request);

        $this->assertEquals($expected, $result);
    }

    public function test_apiLogin_mockRepository_assignApiTokenToUser()
    {
        $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password',
        ]);

        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username',
        ];

        $apiToken = 'generated-token';

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('getUserByUsernamePassword')
            ->with('test-username', 'test-password')
            ->willReturn($user);

        $mockRepository->expects($this->once())
            ->method('assignApiTokenToUser')
            ->with(1)
            ->willReturn($apiToken);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_mockRepositorygetuserByUsernamePassword_responseLoginSuccess()
    {
        $expected = response()->json([
            'success' => true,
            'message' => 'Login successful',
            'api_token' => 'generated-token',
            'user' => [
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]
        ]);

        $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsernamePassword')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);


        $stubRepository->method('assignApiTokenToUser')
            ->willReturn('generated-token');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_mockRepository_authenticateToken()
    {
        $token = 'api_token';

        $request = Request::create(
            '/api/apiUser',
            'GET',
            [],
            [],
            [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token);

        $controller = $this->makeController($mockRepository);
        $controller->apiGetAuthenticatedUser($request);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryauthenticateTokenNullData_returnsUnauthorizedResponse()
    {
        $token = 'invalid-token';

        $expected = response()->json([
            'message' => 'Unauthorized'
        ], 401);

        $request = Request::create(
            '/api/user',
            'GET',
            [],
            [],
            [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryauthenticateTokenHasData_returnsUserDataResponse()
    {
        $token = 'valid-token';

        $expected = response()->json([
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username',
        ]);

        $request = Request::create(
            '/api/user',
            'GET',
            [],
            [],
            [],
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

        $this->assertEquals($expected, $response);
    }

    public function test_apiLogout_mockRepositoryauthenticateToken_bearerTokenPassedToauthenticateToken()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/logout',
            'GET',
            [],
            [],
            [],
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

    public function test_apiLogout_mockRepositoryauthenticateTokenUserExists_CallsClearApiToken()
    {
        $token = 'valid-token';

        $request = Request::create(
            '/api/logout',
            'POST',
            [],
            [],
            [],
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

    public function test_apiLogout_mockRepositoryauthenticateTokenUserNull_doesNotCallClearApiToken()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/logout',
            'POST',
            [],
            [],
            [],
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
        $mockRepository->expects($this->exactly(1))
            ->method('getUserByUsername')
            ->with('test-username')
            ->willReturn((object)[
                'id' => 1,
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_mockRepositorygetUserByUsernameNullData_returnsNotFoundResponse()
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

        $this->assertEquals($expected, $result);
    }

    public function test_apiDeleteUser_mockRepositorydeleteUser_calledWhenUserExists()
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

    public function test_apiDeleteUser_mockRepository_deleteUserResponseSuccessDeletion()
    {
        $expected = response()->json([
            'success' => true,
            'message' => 'Profile deleted successfully.'
        ]);

        $request = new Request([
            'username' => 'test-username',
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn((object)[
                'id' => 1,
                'username' => 'test-username'
            ]);

        $stubRepository->method('deleteUser')
            ->willReturn(true);

        $controller = $this->makeController($stubRepository);
        $result = $controller->apiDeleteUser($request);

        $this->assertEquals($expected, $result);
    }

    public function test_apiUpdate_callsAuthenticateTokenWithBearerToken()
    {
        $token = 'invalid-token';

        $request = Request::create(
            '/api/update',
            'GET',
            [],
            [],
            [],
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

    public function test_apiUpdate_mockRepository_authenticateTokenInvalidToken_returnsUnauthorizedResponse()
    {
        $token = 'invalid-token';

        $expected = response()->json([
            'message' => 'Unauthorized'
        ], 401);

        $request = Request::create(
            '/api/update',
            'GET',
            [],
            [],
            [],
            ['HTTP_Authorization' => 'Bearer ' . $token]
        );

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_invalidRequestData_ValidationException()
    {
        $token = 'valid-token';

        $request = Request::create(
            '/api/update',
            'POST',
            [
                'password' => '',
            ],
            [],
            [],
            [
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

    public function test_apiUpdate_whenUsernameAvailable_returnsOkResponse()
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
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

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

    public function test_apiUpdate_checkUsernameAlreadyTaken_returnsUsernameAlreadyTakenResponse()
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

        $expected = response()->json([
            'error' => 'Username already taken.'
        ], 422);

        $request = Request::create(
            '/api/update',
            'POST',
            [
                'username' => 'taken-username'
            ],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('authenticateToken')
            ->willReturn($currentUser);

        $mockRepository->method('getUserByUsername')
            ->with('taken-username')
            ->willReturn($otherUser);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_updatesNameOnly_andReturnsSuccessResponse()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $expected = response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = Request::create(
            '/api/update',
            'POST',
            ['name' => 'new-test-name'],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

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

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_updatesUsernameOnly_andReturnsSuccessResponse()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $expected = response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = Request::create(
            '/api/update',
            'POST',
            ['username' => 'new-test-username'],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

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

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_updatesPasswordOnly_andReturnsSuccessResponse()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $expected = response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = Request::create(
            '/api/update',
            'POST',
            ['password' => 'new-password'],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

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

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_updatesMultipleFields_andReturnsSuccessResponse()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username',
        ];

        $expected = [
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ];

        $request = Request::create(
            '/api/update',
            'POST',
            [
                'name' => 'new-test-name',
                'username' => 'new-test-username',
            ],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->with('new-test-username')
            ->willReturn(null);

        $mockRepository->expects($this->exactly(1))
            ->method('updateUser')
            ->with(1, [
                'name' => 'new-test-name',
                'username' => 'new-test-username',
            ])
            ->willReturn(true);

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response->getData(true));
    }

    public function test_apiUpdate_ignoresEmptyPassword_andReturnsSuccessResponse()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $expected = response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = Request::create(
            '/api/update',
            'POST',
            ['password' => ''],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->never())
            ->method('updateUser');

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_doesNothingWhenNoFieldsToUpdate_andReturnsSuccessResponse()
    {
        $token =
            'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $expected = response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = Request::create(
            '/api/update',
            'POST',
            [],
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token
            ]
        );

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn($user);

        $mockRepository->expects($this->never())
            ->method('updateUser');

        $controller = $this->makeController($mockRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }
}
