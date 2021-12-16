<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Helpers\ResponseFormatter;

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
}
