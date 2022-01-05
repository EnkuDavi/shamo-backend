<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Requests\UserRequest;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Helpers\ResponseFormatter;
use Illuminate\Support\Facades\Auth;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => ['required','string','max:64'],
                'username' => ['required','string','unique:users,username','max:32'],
                'email' => ['required','email','max:64','unique:users,email'],
                'phone' => ['nullable','numeric'],
                'password' => ['required','string']
            ]);

            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password)
            ]);

            $user = User::where('email', $request->email)->first();
            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                    // 'data' => 'berhasil'
                    'access_token' => $tokenResult,
                    'token_type' => 'Bearer',
                    'user' => $user
            ], 'Success Registered');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function login(UserRequest $request)
    {
        try {
            $credentials = request(['email','password']);
            if(!Auth::attempt($credentials)){
                return ResponseFormatter::error(['message' => 'Unauthorized'], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();
            if(!Hash::check($request->password, $user->password,[])){
                throw new \Exception("Invalid Password");
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($token, 'Token Revoked');
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data berhasil diambil');
    }

    public function update(Request $request)
    {
       try {
            $data = $request->all();
            $user = Auth::user();
            $user->update($data);
            return ResponseFormatter::success($user, 'Profile');
       } catch (Exception $error) {
           return ResponseFormatter::error([
               'error' => $error
           ],'Failed', 500);
       }
    }
}
