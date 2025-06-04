<?php

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Repositories\UserRepository;
use App\Http\Controllers\UserController;
use Illuminate\Foundation\Exceptions\Renderer\Exception;
use Illuminate\Validation\ValidationException;

class UserControllerTest extends TestCase
{
    public function makeController($repository = null)
    {
        $repository ??= $this->createMock(UserRepository::class);

        return new UserController($repository);
    }

    #[DataProvider('registerDataParams')]
    public function test_apiRegister_missingRequestData_ValidationException($parameter)
    {
        $this->expectException(ValidationException::class);

        $requestData = [
            'name' => 'testName',
            'username' => 'testUsername',
            'password' => 'testPassword'
        ];

        unset($requestData[$parameter]);

        $request = new Request($requestData);

        $controller = $this->makeController();
        $controller->apiRegister($request);
    }

    public static function registerDataParams()
    {
        return [
            ['name'],
            ['username'],
            ['password']
        ];
    }

    public function test_apiRegister_mockRepository_getUserByUsername()
    {
        $request = new Request([
            'name' => 'testName',
            'username' => 'testUsername',
            'password' => 'testPassword'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('testUsername')
            ->willReturn((object)[]);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

    public function test_apiRegister_stubRepositoryUsernameAlreadyExist_returnsUsernameAlreadyTaken()
    {
        $expected = new JsonResponse([
            'message' => 'Username already taken'
        ], 409);

        $request = new Request([
            'name' => 'testName',
            'username' => 'testUsername',
            'password' => 'testPassword'
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
            'name' => 'testName',
            'username' => 'testUsername',
            'password' => 'testPassword'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->once())
            ->method('createUser')
            ->with('testName', 'testUsername', 'testPassword')
            ->willReturn((object)[
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiRegister($request);
    }

    public function test_apiRegister_stubRepositoryUsernameNotExisting_returnsRegisterSuccess()
    {
        $expected = new JsonResponse([
            'message' => 'User Registered Successfully',
            'user' => [
                'name' => 'testName',
                'username' => 'testUsername'
            ]
        ], 201);

        $request = new Request([
            'name' => 'testName',
            'username' => 'testUsername',
            'password' => 'testPassword'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('createUser')
            ->willReturn((object)[
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiRegister($request);

        $this->assertEquals($expected, $response);
    }

    #[DataProvider('loginDataParams')]
    public function test_apiLogin_missingRequestData_ValidationException($parameter)
    {
        $this->expectException(ValidationException::class);

        $requestData = [
            'username' => 'testUsername',
            'password' => 'testPassword'
        ];
        unset($requestData[$parameter]);

        $request = new Request($requestData);

        $controller = $this->makeController();
        $controller->apiLogin($request);
    }

    public static function loginDataParams()
    {
        return [
            ['username'],
            ['password']
        ];
    }

    public function test_apiLogin_mockRepository_getUserByUsernamePassword()
    {
        $request = new Request([
            'username' => 'testUsername',
            'password' => 'testPassword'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('getUserByUsernamePassword')
            ->with('testUsername', 'testPassword')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
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
            'username' => 'testUsername',
            'password' => 'testPassword'
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
            'username' => 'testUsername',
            'password' => 'testPassword'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('getUserByUsernamePassword')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $mockRepository->expects($this->once())
            ->method('assignApiTokenToUser')
            ->with(1);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogin($request);
    }

    public function test_apiLogin_stubRepositoryHasUserData_returnsLoginSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'Login successful',
            'api_token' => 'testToken',
            'user' => [
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]
        ]);

        $request = new Request([
            'username' => 'testUsername',
            'password' => 'testPassword'
        ]);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsernamePassword')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $stubRepository->method('assignApiTokenToUser')
            ->willReturn('testToken');

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiLogin($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_mockRepository_authenticateToken()
    {
        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with('testToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiGetAuthenticatedUser($request);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryNullTokenData_returnsUnauthorizedResponse()
    {
        $expected = new JsonResponse([
            'message' => 'Unauthorized'
        ], 401);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer invalidToken');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiGetAuthenticatedUser_stubRepositoryHasTokenData_returnsUserData()
    {
        $expected = new JsonResponse([
            'id' => 1,
            'name' => 'testName',
            'username' => 'testUsername',
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiGetAuthenticatedUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiLogout_mockRepository_authenticateToken()
    {
        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $mockRepository = $this->createMock(UserRepository::class);

        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with('testToken')
            ->willReturn((object)['id' => 1]);

        $controller = $this->makeController($mockRepository);
        $controller->apiLogout($request);
    }

    public function test_apiLogout_mockRepository_clearApiToken()
    {
        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

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
            'message' => 'You have been logged out.'
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

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
            'username' => 'testUsername'
        ]);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('testUsername')
            ->willReturn((object)['id' => 1]);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_stubRepositoryNullUserData_returnsUserNotFound()
    {
        $expected = new JsonResponse([
            'success' => false,
            'message' => 'User not found.'
        ], 404);

        $request = new Request(['username' => 'testUsername']);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiDeleteUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiDeleteUser_mockRepository_deleteUser()
    {
        $request = new Request(['username' => 'testUsername']);

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('getUserByUsername')
            ->willReturn((object)['id' => 1]);

        $mockRepository->expects($this->once())
            ->method('deleteUser')
            ->with(1);

        $controller = $this->makeController($mockRepository);
        $controller->apiDeleteUser($request);
    }

    public function test_apiDeleteUser_stubRepository_returnsDeletedSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'Profile deleted successfully.'
        ]);

        $request = new Request(['username' => 'testUsername']);

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('getUserByUsername')
            ->willReturn((object)['id' => 1]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiDeleteUser($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_authenticateToken()
    {
        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('authenticateToken')
            ->with('testToken')
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
        $request->headers->set('Authorization', 'Bearer invalidToken');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn(null);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    public function test_apiUpdate_mockRepository_getUserByUsername()
    {
        $request = new Request([
            'name' => 'testName',
            'username' => 'newUsername'
        ]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

        $mockRepository->expects($this->once())
            ->method('getUserByUsername')
            ->with('newUsername')
            ->willReturn(null);

        $mockRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'newUsername'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_stubRepositoryUsernameAlreadyExist_returnsUsernameAlreadyTaken()
    {
        $expected = new JsonResponse([
            'error' => 'Username already taken.'
        ], 422);

        $request = new Request(['username' => 'takenUsername']);

        $request->headers->set('Authorization', 'Bearer testToken');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

        $stubRepository->method('getUserByUsername')
            ->willReturn((object)['id' => 2]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }

    #[DataProvider('updateDataParams')]
    public function test_apiUpdate_mockRepository_updateUser($parameter)
    {
        $request = new Request($parameter);
        $request->headers->set('Authorization', 'Bearer testToken');

        if (isset($parameter['password'])){
            $parameter['password'] = md5($parameter['password']);
        }

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->once())
            ->method('updateUser')
            ->with(1, $parameter);

        $mockRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public static function updateDataParams()
    {
        return [
            [['name' => 'testName']],
            [['username' => 'testUsername']],
            [['password' => 'testPassword']],
            [[
                'name' => 'testName',
                'username' => 'testUsername'

            ]],
            [[
                'username' => 'testUsername',
                'password' => 'testPassword',
            ]],
            [[
                'name' => 'testName',
                'password' => 'testPassword',
            ]],
            [[
                'name' => 'testName',
                'username' => 'testUsername',
                'password' => 'testPassword',
            ]]
        ];
    }

    public function test_apiUpdate_mockRepository_getUserById()
    {
        $request = new Request([
            'username' => 'newUsername'
        ]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

        $mockRepository->method('getUserByUsername')
            ->willReturn(null);

        $mockRepository->expects($this->once())
            ->method('getUserById')
            ->with(1)
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'newUsername'
            ]);

        $controller = $this->makeController($mockRepository);
        $controller->apiUpdate($request);
    }

    public function test_apiUpdate_stubRepositoryUserUpdated_returnsUpdateSuccess()
    {
        $expected = new JsonResponse([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'testName',
                'username' => 'testUsername',
            ]
        ]);

        $request = new Request([]);
        $request->headers->set('Authorization', 'Bearer testToken');

        $stubRepository = $this->createMock(UserRepository::class);
        $stubRepository->method('authenticateToken')
            ->willReturn((object)['id' => 1]);

        $stubRepository->method('getUserByUsername')
            ->willReturn(null);

        $stubRepository->method('getUserById')
            ->willReturn((object)[
                'id' => 1,
                'name' => 'testName',
                'username' => 'testUsername'
            ]);

        $controller = $this->makeController($stubRepository);
        $response = $controller->apiUpdate($request);

        $this->assertEquals($expected, $response);
    }
}
