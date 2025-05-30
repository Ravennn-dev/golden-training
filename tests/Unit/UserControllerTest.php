<?php

namespace Tests\Unit;

use Js;
use Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
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

    public function test_apiRegister_missingRequestData_ValidationException()
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
        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('test-username')
            ->willReturn((object)['test']);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

    public function test_apiRegister_stubRepositoryHasData_returnsUsernameAlreadyTaken()
    {
        $expected = new JsonResponse([
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
        $response = $controller->apiRegister($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiRegister_mockRepository_createUser()
    {
        $request = new Request([
            'name' => 'test',
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('createUser')
            ->with('test', 'test-username', 'test-password')
            ->willReturn((object)[
                'name' => 'name',
                'username' => 'username'
            ]);

        $mockRepository->method('getUserByUsername')->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

    public function test_apiRegister_stubRepositoryNullData_returnsRegisterSuccess()
    {
        $expected = new JsonResponse([
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
        $stubRepository->method('getUserByUsername')->willReturn(null);

        $stubRepository->method('createUser')
            ->willReturn((object)[
                'name' => 'name',
                'username' => 'username'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiRegister($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiLogin_missingRequestData_ValidationException()
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
        $mockRepository->expects($this->once())
            ->method('getUserByUsernamePassword')
            ->with('test-username', 'test-password')
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_stubRepositoryNullData_returnsInvalidCredentials()
    {
        $expected = new JsonResponse([
            'success' => false,
            'message' => 'Invalid credentials'
        ], 401);

        $request = new Request([
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsernamePassword')->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals($expected, $response);
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

        $mockRepository->method('getUserByUsernamePassword')->willReturn($user);

        $mockRepository->expects($this->once())
            ->method('assignApiTokenToUser')
            ->willReturn($apiToken);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_stubRepositoryHasData_returnsLoginSuccess()
    {
        $expected = new JsonResponse([
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

        $stubRepository->method('assignApiTokenToUser')->willReturn('generated-token');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_mockRepository_authenticateToken()
    {
        $token = 'api_token';

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiGetAuthenticatedUser($request);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryNullData_returnsUnauthorizedResponse()
    {
        $token = 'invalid-token';

        $expected = new JsonResponse([
            'message' => 'Unauthorized'
        ], 401);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryHasData_returnsUserData()
    {
        $token = 'valid-token';
        $expected = new JsonResponse([
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username',
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

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

    public function test_apiLogout_mockRepository_authenticateToken()
    {
        $token = 'token';

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogout($request);
    }

    public function test_apiLogout_mockRepository_clearApiToken()
    {
        $token = 'valid-token';

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $user = (object)['id' => 1];

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('authenticateToken')->willReturn($user);

        $mockRepository->expects($this->once())
            ->method('clearApiToken')
            ->with($user->id);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogout($request);
    }

    public function test_apiLogout_stubRepositoryNullData_doesNotCallClearApiToken()
    {
        $token = 'invalid-token';

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')->willReturn(null);
        $stubRepository->expects($this->never())->method('clearApiToken');

        $controller = $this->makeController($stubRepository);
        $controller->apiLogout($request);
    }

    public function test_apiLogout_stubRepositoryHasData_returnsLogOutSuccess()
    {
        $token = 'token';

        $expected = new JsonResponse([
            'message' => 'You have been logged out.',
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $user = (object)['id' => 1];

        $stubRepository = $this->createMock(UserRepository::class);

        $stubRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn($user);

        $stubRepository->method('clearApiToken');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiLogout($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiDeleteUser_invalidRequestData_ValidationException()
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
                'id' => 1,
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_stubRepositoryNullData_returnsUserNotFound()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $expected = new JsonResponse([
            'success' => false,
            'message' => 'User not found.'
        ], 404);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')->willReturn(null);

        $controller = new UserController($stubRepository);
        $response = $controller->apiDeleteUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiDeleteUser_mockRepository_deleteUser()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $user = (object)[
            'id' => 1,
            'username' => 'test-username',
        ];

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('getUserByUsername')->willReturn($user);

        $mockRepository->expects($this->once())
            ->method('deleteUser')
            ->with($user->id)
            ->willReturn(true);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_stubRepositoryHasData_returnsDeletedSuccess()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $expected = new JsonResponse([
            'success' => true,
            'message' => 'Profile deleted successfully.'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn((object)[
                'id' => 1,
                'username' => 'test-username'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiDeleteUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_authenticateToken()
    {
        $token = 'token';

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_stubRepositoryNullData_returnsUnauthorized()
    {
        $token = 'invalid-token';

        $expected = new JsonResponse([
            'message' => 'Unauthorized'
        ], 401);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_getUserByUsername()
    {
        $token = 'token';
        $username = 'new-username';

        $request = new Request(
            [
                'name' => 'test',
                'username' => $username
            ],
        );
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('authenticateToken')
            ->with($token)
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with($username)
            ->willReturn(null);

        $mockRepository->method('updateUser');

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }
    public function test_apiUpdate_stubRepositoryHasData_returnsUsernameAlreadyTaken()
    {
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

        $expected = new JsonResponse([
            'error' => 'Username already taken.'
        ], 422);

        $request = new Request([
            'username' => 'taken-username'
        ]);
        $request->headers->set('Authorization', 'Bearer valid-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')->willReturn($currentUser);

        $stubRepository->method('getUserByUsername')
            ->with('taken-username')
            ->willReturn($otherUser);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_updateUser()
    {
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $request = new Request([
            'username' => 'new-username'
        ]);
        $request->headers->set('Authorization', 'Bearer valid-token');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')->willReturn($user);

        $mockRepository->method('getUserByUsername')
            ->with('new-username')
            ->willReturn(null);

        $mockRepository->method('updateUser');

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_stubRepositoryUpdateNameOnly_returnsUpdateSuccess()
    {
        $token = 'valid-token';
        $user = (object)[
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username'
        ];

        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = new Request([
            'name' => 'new-test-name'
        ]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')->willReturn($user);
        $stubRepository->method('getUserByUsername')->willReturn(null);

        $stubRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['name' => 'new-test-name']);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_stubRepositoryUpdateUserNameOnly_returnsUpdateSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = new Request([
            'username' => 'new-test-username'
        ],);
        $request->headers->set('Authorization', 'Bearer valid-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $stubRepository->method('getUserByUsername')->willReturn(null);

        $stubRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['username' => 'new-test-username']);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_stubRepositoryUpdatePasswordOnly_returnsUpdateSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = new Request([
            'password' => 'new-password'
        ],);
        $request->headers->set('Authorization', 'Bearer valid-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);
        $stubRepository->method('getUserByUsername')->willReturn(null);

        $stubRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['password' => md5('new-password')]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_stubRepositoryUpdatesMultipleFields_returnsUpdateSuccess()
    {
        $expected = [
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ];

        $request = new Request(
            [
                'name' => 'new-test-name',
                'username' => 'new-test-username',
            ],
        );
        $request->headers->set('Authorization', 'Bearer valid-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username',
            ]);

        $stubRepository->method('getUserByUsername')
            ->with('new-test-username')
            ->willReturn(null);

        $stubRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, [
                'name' => 'new-test-name',
                'username' => 'new-test-username',
            ])
            ->willReturn(true);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response->getData(true));
    }

    public function test_apiUpdate_stubRepositoryEmptyPassword_returnsUpdateSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = new Request([
            'password' => ''
        ],);
        $request->headers->set('Authorization', 'Bearer valid-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $stubRepository->method('getUserByUsername')->willReturn(null);

        $stubRepository->expects($this->never())->method('updateUser');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_stubRepositoryEmptyFields_returnsUpdateSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'test',
                'username' => 'test-username',
            ]
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer valid-tokenfille');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $stubRepository->expects($this->never())->method('updateUser');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }
}
