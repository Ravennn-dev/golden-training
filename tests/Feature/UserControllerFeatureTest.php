<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Foundation\Testing\RefreshDatabase;

class UserControllerFeatureTest extends TestCase
{
    use RefreshDatabase;

    public function test_apiRegister_validatesInput()   //validates input
    {
        $response = $this->postJson('/api/apiRegister', [
            'name' => '',
            'username' => '',
            'password' => ''
        ]);
        $response->assertJsonValidationErrors(['name', 'username', 'password']);

        $response = $this->postJson('/api/apiRegister', [
            'name' => 'Test'
        ]);
        $response->assertJsonValidationErrors(['username', 'password']);

        $response = $this->postJson('/api/apiRegister', [
            'username' => 'test-username'
        ]);
        $response->assertJsonValidationErrors(['name', 'password']);

        $response = $this->postJson('/api/apiRegister', [
            'password' => 'test-password'
        ]);
        $response->assertJsonValidationErrors(['name', 'username']);

        $response = $this->postJson('/api/apiRegister', [
            'name' => 'test',
            'username' => 'test-username'
        ]);
        $response->assertJsonValidationErrors(['password']);

        $response = $this->postJson('/api/apiRegister', [
            'name' => 'test',
            'password' => 'test-password'
        ]);
        $response->assertJsonValidationErrors(['username']);

        $response = $this->postJson('/api/apiRegister', [
            'username' => 'test-username',
            'password' => 'test-password'
        ]);
        $response->assertJsonValidationErrors(['name']);
    }

    public function test_apiRegister_userCanRegister() //success register
    {
        $userData = [
            'name' => 'User',
            'username' => 'username1',
            'password' => md5('userpass'),
        ];

        $response = $this->postJson('/api/apiRegister', $userData);
        $response->assertStatus(201)
            ->assertJson([
                'message' => 'User Registered Successfully',
                'user' => [
                    'name' => 'User',
                    'username' => 'username1'
                ]
            ]);
    }

    public function test_apiRegister_takenUsernameThrowsError() //already taken username
    {
        $userData = [
            'name' => 'test',
            'username' => 'taken-username',
            'password' => 'test-password'
        ];

        User::create([
            'name' => 'test',
            'username' => 'taken-username',
            'password' => md5('test-password')
        ]);

        $this->assertDatabaseHas('users', ['username' => 'taken-username']);

        $response = $this->postJson('/api/apiRegister', $userData);
        $response->assertStatus(409);
        $response->assertJson([
            'message' => 'Username already taken'
        ]);
    }

    public function test_apiLogin_validatesInput()  //validates input
    {
        $response = $this->postJson('/api/apiLogin', [
            'username' => '',
            'password' => ''
        ]);
        $response->assertJsonValidationErrors(['username', 'password']);

        $response = $this->postJson('/api/apiLogin', [
            'username' => 'test-name',
            'password' => ''
        ]);
        $response->assertJsonValidationErrors(['password']);
        $response = $this->postJson('/api/apiLogin', [
            'username' => '',
            'password' => 'test-password'
        ]);
        $response->assertJsonValidationErrors(['username']);
    }

    public function test_apiLogin_loginWithValidCredentials()   //successful login
    {
        $user = User::create([
            'name' => 'test',
            'username' => 'test-username',
            'password' => md5('test-password'),
        ]);

        $response = $this->postJson('/api/apiLogin', [
            'username' => 'test-username',
            'password' => 'test-password'
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'message',
                'api_token',
                'user' => [
                    'id',
                    'name',
                    'username'
                ]
            ])
            ->assertJson([
                'success' => true,
                'message' => 'Login successful',
                'user' => [
                    'id' => $user->id,
                    'name' => 'test',
                    'username' => 'test-username'
                ]
            ]);

        $responseArray = $response->json();
        $this->assertNotEmpty($responseArray['api_token']);
    }

    public function test_apiLogin_invalidUsername()  //error "Invalid credentials"
    {
        User::create([
            'name' => 'test',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);

        $response = $this->postJson('/api/apiLogin', [
            'username' => 'invalid-username',
            'password' => 'wrong-password'
        ]);

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
                'message' => 'Invalid credentials'
            ]);

        $response->assertJsonMissing(['api_token']);
    }

    public function test_apiLogin_invalidPassword()  //login with wrong password
    {
        User::create([
            'name' => 'test',
            'username' => 'test-username',
            'password' => md5('correctpassword')
        ]);

        $response = $this->postJson('/api/apiLogin', [
            'username' => 'test-username',
            'password' => 'wrongpassword'
        ]);

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
                'message' => 'Invalid credentials'
            ]);
    }

    public function test_apiLogout_successfulLogout() // logout
    {
        $apiToken = 'api-token';

        $user = User::create([
            'name' => 'test',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => $apiToken,
        ]);


        $response = $this->postJson(
            '/api/apiLogout',
            [],
            [
                'Authorization' => 'Bearer ' . $apiToken
            ]
        );

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'You have been logged out.'
            ]);
        $user->refresh();
        $this->assertNull($user->api_token);
    }

    public function test_apiDeleteUser_returnsSuccessResponse()   //delete success
    {
        User::create([
            'name' => 'test',
            'username' => 'test-username',
            'password' => md5('test-password'),
        ]);

        $response = $this->deleteJson('/api/apiDeleteUser', [
            'username' => 'test-username'
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Profile deleted successfully.'
            ]);

        $this->assertDatabaseMissing('users', [
            'username' => 'test-username'
        ]);
    }

    public function test_apiUpdate_canUpdateNameOnly()
    {
        $user = User::create([
            'name' => 'original-name',
            'username' => 'original-username',
            'password' => md5('original-password'),
            'api_token' => 'test-token',
        ]);

        $response = $this->patchJson(
            '/api/apiUpdate',
            ['name' => 'new-name'],
            ['Authorization' => 'Bearer test-token']
        );

        $user->refresh();
        $this->assertEquals('new-name', $user->name);
        $this->assertEquals('original-username', $user->username);
        $this->assertEquals(md5('original-password'), $user->password);

        $response->assertStatus(200);
    }
    public function test_apiUpdate_canUpdateUsernameOnly()
    {
        $user = User::create([
            'name' => 'original-name',
            'username' => 'new-username',
            'password' => md5('original-password'),
            'api_token' => 'test-token',
        ]);

        $response = $this->patchJson(
            '/api/apiUpdate',
            ['username' => 'new-username'],
            ['Authorization' => 'Bearer test-token']
        );

        $user->refresh();
        $this->assertEquals('original-name', $user->name);
        $this->assertEquals('new-username', $user->username);
        $this->assertEquals(md5('original-password'), $user->password);

        $response->assertStatus(200);
    }

    public function test_apiUpdate_canUpdatePasswordOnly()
    {
        $user = User::create([
            'name' => 'original-name',
            'username' => 'original-username',
            'password' => md5('original-password'),
            'api_token' => 'test-token',
        ]);

        $response = $this->patchJson(
            '/api/apiUpdate',
            ['password' => 'new-password'],
            ['Authorization' => 'Bearer test-token']
        );

        $user->refresh();
        $this->assertEquals(md5('new-password'), $user->password);
        $this->assertEquals('original-name', $user->name);
        $this->assertEquals('original-username', $user->username);

        $response->assertStatus(200);
    }

    public function test_apiUpdate_canUpdateMultipleFields()
    {
        $user = User::create([
            'name' => 'original-name',
            'username' => 'original-username',
            'password' => md5('original-password'),
            'api_token' => 'test-token',
        ]);

        $response = $this->patchJson(
            '/api/apiUpdate',
            [
                'name' => 'new-name',
                'username' => 'new-username',
                'password' => 'new-password'
            ],
            ['Authorization' => 'Bearer test-token']
        );

        $user->refresh();
        $this->assertEquals('new-name', $user->name);
        $this->assertEquals('new-username', $user->username);
        $this->assertEquals(md5('new-password'), $user->password);

        $response->assertStatus(200);
    }

    public function test_apiUpdate_emptyPasswordDoesNotUpdatePassword()
    {
        $user = User::create([
            'name' => 'Original Name',
            'username' => 'original_username',
            'password' => md5('original_password'),
            'api_token' => 'test-token',
        ]);

        $originalPassword = $user->password;

        $response = $this->patchJson(
            '/api/apiUpdate',
            ['password' => ''],
            ['Authorization' => 'Bearer test-token']
        );

        $this->assertEquals($originalPassword, $user->password);

        $response->assertStatus(200);
    }

    public function test_apiUpdate_updateUsernameWithAlreadyTakenUsername()
    {
        $user = User::create([
            'name' => 'Original Name',
            'username' => 'original_username',
            'password' => md5('original_password'),
            'api_token' => 'test-token',
        ]);

        User::create([
            'name' => 'Conflict User',
            'username' => 'taken_username',
            'password' => md5('conflict_password'),
            'api_token' => 'conflict-token',
        ]);

        $response = $this->patchJson(
            '/api/apiUpdate',
            ['username' => 'taken_username'],
            ['Authorization' => 'Bearer test-token']
        );

        $response->assertStatus(422)
            ->assertJsonFragment(['error' => 'Username already taken.']);

        $user->refresh();
        $this->assertEquals('original_username', $user->username);
    }
}
