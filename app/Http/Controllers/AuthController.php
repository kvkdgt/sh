<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{

    public function Signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6',
            'confirm_password' => 'required|string|same:password',
        ], [
            'first_name.required' => 'The first name field is required.',
            'last_name.required' => 'The last name field is required.',
            'email.required' => 'The email field is required.',
            'email.email' => 'Please provide a valid email address.',
            'email.unique' => 'This email is already taken.',
            'password.required' => 'The password field is required.',
            'password.min' => 'The password must be at least 6 characters.',
            'confirm_password.required' => 'The confirm password field is required.',
            'confirm_password.same' => 'The confirm password must match the password field.',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'first_name' => $request->input('first_name'),
            'last_name' => $request->input('last_name'),
            'email' => $request->input('email'),
            'password' => bcrypt($request->input('password')),
        ]);

        return response()->json(['message' => 'User added successfully', 'user' => $user], 200);
    }

    public function SignIn(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ], [
            'email.required' => 'The email field is required.',
            'email.email' => 'Please provide a valid email address.',
            'password.required' => 'The password field is required.',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->input('email'))->first();
        if (!$user || !password_verify($request->input('password'), $user->password)) {
            return response()->json(['error' => 'The provided credentials are incorrect.'], 401);
        }


        if (Auth::loginUsingId($user->id)) {
            $token = $user->createToken('AuthToken')->plainTextToken;

            return response()->json(['message' => 'Logged in successfully', 'user' => $user, 'token' => $token], 200);
        }

        return response()->json(['error' => 'Could not log in.'], 401);
    }

    public function SignOut(Request $request)
    {
        // Auth::guard('web')->logout(); // For web-based authentication, change 'web' to your guard name if different
        $user = Auth::user(); // Retrieve the authenticated user

        // Auth::guard('web')->logout(); // For web-based authentication, change 'web' if different
        // Invalidate the token or session data on the client-side if necessary

        return response()->json(['message' => 'Logged out successfully', 'user' => $user], 200);
    }

    public function ChangePassword(Request $request)
    {

        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'current_password' => 'required|string',
                'password' => 'required|string|min:6',
                'confirm_password' => 'required|string|same:password',
            ], [
                'email.required' => 'The email field is required.',
                'email.email' => 'Please provide a valid email address.',
                'current_password.required' => 'The current password field is required.',
                'password.required' => 'The new password field is required.',
                'password.min' => 'The new password must be at least 6 characters.',
                'confirm_password.required' => 'The confirm password field is required.',
                'confirm_password.same' => 'The confirm password must match the new password.',
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 422);
            }

            $user = User::where('email', $request->input('email'))->first();

            if (!$user || !password_verify($request->input('current_password'), $user->password)) {
                return response()->json(['error' => 'The provided credentials are incorrect.'], 401);
            }

            // Change the user's password
            $user->password = bcrypt($request->input('password'));
            $user->save();

            return response()->json(['message' => 'Password updated successfully', 'user' => $user], 200);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }
}
