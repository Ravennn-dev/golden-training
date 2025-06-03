<?php

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
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

    public function test_apiRegister_stubRepositoryUsernameAlreadyExist_returnsUsernameAlreadyTaken()
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
        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->once())
            ->method('createUser')
            ->with('test', 'test-username', 'test-password')
            ->willReturn((object)[
                'name' => 'name',
                'username' => 'username'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

    public function test_apiRegister_stubRepositoryNullTokenData_returnsRegisterSuccess()
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
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

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
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_stubRepositoryNullUserData_returnsInvalidCredentials()
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
        $stubRepository->method('getUserByUsernamePassword')
            ->willReturn(null);

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

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('getUserByUsernamePassword')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username',
            ]);

        $mockRepository->expects($this->once())
            ->method('assignApiTokenToUser')
            ->willReturn('test-token');

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_stubRepositoryHasUserData_returnsLoginSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'Login successful',
            'api_token' => 'test-token',
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
            ->willReturn('test-token');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_mockRepository_authenticateToken()
    {
        $token = 'test-token';

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiGetAuthenticatedUser($request);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryNullTokenData_returnsUnauthorizedResponse()
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

    public function test_apiGetAuthenticatedUser_stubRepositoryHasTokenData_returnsUserData()
    {
        $token = 'test-token';
        $expected = new JsonResponse([
            'id' => 1,
            'name' => 'test',
            'username' => 'test-username',
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->with($token)
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiLogout_mockRepository_authenticateToken()
    {
        $token = 'test-token';

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
        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer test-token');

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

        $mockRepository->expects($this->once())
            ->method('clearApiToken')
            ->with(1);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogout($request);
    }

    public function test_apiLogout_stubRepositoryTokenHasData_returnsLogOutSuccess()
    {
        $expected = new JsonResponse([
            'message' => 'You have been logged out.',
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

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

    public function test_apiDeleteUser_stubRepositoryNullUserData_returnsUserNotFound()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $expected = new JsonResponse([
            'success' => false,
            'message' => 'User not found.'
        ], 404);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $controller = new UserController($stubRepository);
        $response = $controller->apiDeleteUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiDeleteUser_mockRepository_deleteUser()
    {
        $request = new Request([
            'username' => 'test-username',
        ]);

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('getUserByUsername')
            ->willReturn((object)[
                'id' => 1,
                'username' => 'test-username',
            ]);

        $mockRepository->expects($this->once())
            ->method('deleteUser')
            ->with(1);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_stubRepositoryUsernameHasData_returnsDeletedSuccess()
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
        $token = 'test-token';

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with($token)
            ->willReturn(null);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_stubRepositoryNullTokenData_returnsUnauthorized()
    {
        $expected = new JsonResponse([
            'message' => 'Unauthorized'
        ], 401);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer invalid-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_getUserByUsername()
    {
        $request = new Request(
            [
                'name' => 'test',
                'username' => 'new-test-username'
            ],
        );
        $request->headers->set('Authorization', 'Bearer test-token');

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('new-test-username')
            ->willReturn(null);

        $mockRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'new-test-username'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }
    public function test_apiUpdate_stubRepositoryUsernameAlreadyExist_returnsUsernameAlreadyTaken()
    {
        $expected = new JsonResponse([
            'error' => 'Username already taken.'
        ], 422);

        $request = new Request([
            'username' => 'taken-username'
        ]);
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $stubRepository->method('getUserByUsername')
            ->willReturn((object)[
                'id' => 2,
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_updateUser()
    {
        $request = new Request([
            'username' => 'new-username'
        ]);
        $request->headers->set('Authorization', 'Bearer test-token');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
            ]);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, ['username' => 'new-username']);

        $mockRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'new-username'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_mockRepository_getUserById()
    {
        $request = new Request([
            'username' => 'new-username'
        ]);
        $request->headers->set('Authorization', 'Bearer test-token');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->once())
            ->method('getUserById')
            ->with(1)
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'new-username'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_stubRepositoryUpdateNameOnly_returnsUpdateSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'new-test-name',
                'username' => 'test-username',
            ]
        ]);

        $request = new Request([
            'name' => 'new-test-name'
        ]);
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);

        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('updateUser')
            ->with(1, ['name' => 'new-test-name']);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'new-test-name',
                'username' => 'test-username'
            ]);

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
                'username' => 'new-test-username',
            ]
        ]);

        $request = new Request([
            'username' => 'new-test-username'
        ],);
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('updateUser')
            ->with(1, ['username' => 'new-test-username']);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'new-test-username'
            ]);

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
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('updateUser')
            ->with(1, ['password' => md5('new-password')]);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

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
                'name' => 'new-test-name',
                'username' => 'new-test-username',
            ]
        ];

        $request = new Request(
            [
                'name' => 'new-test-name',
                'username' => 'new-test-username',
                'password' => 'new-password'
            ],
        );
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('updateUser')
            ->with(1, [
                'name' => 'new-test-name',
                'username' => 'new-test-username',
                'password' => md5('new-password')
            ]);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'new-test-name',
                'username' => 'new-test-username'
            ]);

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
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

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
        $request->headers->set('Authorization', 'Bearer test-token');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1
            ]);

        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'test',
                'username' => 'test-username'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }
}
