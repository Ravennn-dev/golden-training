<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Foundation\Testing\RefreshDatabase;

class UserControllerFeatureTest extends TestCase
{
    use RefreshDatabase;

    public function test_apiRegister_invalidRequest_expectedData()  //validates input
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

    public function test_apiRegister_validData_expectedData()   //success register
    {
        $userData = [
            'name' => 'User',
            'username' => 'username1',
            'password' => md5('userpass'),
        ];

        $response = $this->postJson('/api/apiRegister', $userData);
        $response->assertJson([
            'message' => 'User Registered Successfully',
            'user' => [
                'name' => 'User',
                'username' => 'username1'
            ]
        ]);

        $response->assertStatus(201);
    }

    public function test_apiRegister_usernameAlreadyTaken_expectedData()    //already taken username
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
        $response->assertJson([
            'message' => 'Username already taken'
        ]);

        $response->assertStatus(409);
    }

    public function test_apiLogin_invalidRequest_expectedData()  //validates input
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

    public function test_apiLogin_validRequest_expectedData()   //successful login
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

        $response->assertJson([
            'success' => true,
            'message' => 'Login successful',
            'user' => [
                'id' => $user->id,
                'name' => 'test',
                'username' => 'test-username'
            ]
        ]);

        $response->assertStatus(200);

        $responseArray = $response->json();
        $this->assertNotEmpty($responseArray['api_token']);
    }

    public function test_apiLogin_usernameNotFound()  //error "Invalid credentials""
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

    public function test_apiLogin_passwordNotFound()  //login with wrong password
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

    public function test_apiLogout_validRequest_expectedData() // logout success
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

    public function test_apiDeleteUser_validRequest_expectedData()   //delete success
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

    public function test_apiUpdate_validRequest_expectedData()
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

    /**
     * @dataProvider requiredStoreValidationProvider
     */
    public function test_apiUpdate_handlesFieldUpdatesAndValidationErrorsCorrectly(
        array $updateData,
        array $expected,
        int $expectedStatus,
        ?string $expectedError
    ) {
        User::create([
            'name' => 'Conflict User',
            'username' => 'taken_username',
            'password' => md5('conflict_password'),
            'api_token' => 'conflict-token',
        ]);

        $user = User::create([
            'name' => $expected['name'],
            'username' => $expected['username'],
            'password' => md5($expected['password']),
            'api_token' => 'test-token',
        ]);

        $response = $this->patchJson('/api/apiUpdate', $updateData, [
            'Authorization' => 'Bearer test-token'
        ]);

        $user->refresh();

        $this->assertEquals($expected['name'], $user->name);
        $this->assertEquals($expected['username'], $user->username);
        $this->assertEquals(md5($expected['password']), $user->password);

        $response->assertStatus($expectedStatus);

        if ($expectedError !== null) {
            $response->assertJsonFragment(['error' => $expectedError]);
        }
    }

    public static function requiredStoreValidationProvider(): array
    {
        return [
            'update_name_only' => [
                ['name' => 'new-name'],
                [
                    'name' => 'new-name',
                    'username' => 'original-username',
                    'password' => 'original-password',
                ],
                200,
                null
            ],
            'update_username_only' => [
                ['username' => 'new-username'],
                [
                    'name' => 'original-name',
                    'username' => 'new-username',
                    'password' => 'original-password',
                ],
                200,
                null
            ],
            'update_password_only' => [
                ['password' => 'new-password'],
                [
                    'name' => 'original-name',
                    'username' => 'original-username',
                    'password' => 'new-password',
                ],
                200,
                null
            ],
            'empty_password_does_not_update' => [
                ['password' => ''],
                [
                    'name' => 'Original Name',
                    'username' => 'original-username',
                    'password' => 'original-password',
                ],
                200,
                null
            ],
            'username_already_taken' => [
                ['username' => 'taken_username'],
                [
                    'name' => 'Original Name',
                    'username' => 'original-username',
                    'password' => 'original-password',
                ],
                422,
                'Username already taken.'
            ], //error expected here
        ];
    }
}
