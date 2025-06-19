<?php

namespace App\Models;
// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Hash;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use App\Notifications\CustomVerifyEmail;

/**
 * @OA\Schema(
 *     schema="User",
 *     type="object",
 *     title="User Model",
 *     description="User model representing an application user.",
 *     required={"iduser", "fullname", "email", "datebirthday", "gender", "role"},
 *     @OA\Property(property="iduser", type="string", format="uuid", description="Primary key UUID of the user", example="a1b2c3d4-e5f6-7890-1234-567890abcdef"),
 *     @OA\Property(property="fullname", type="string", description="User's full name", example="Jane Doe"),
 *     @OA\Property(property="email", type="string", format="email", description="User's email address", example="jane.doe@example.com"),
 *     @OA\Property(property="datebirthday", type="string", format="date", description="User's date of birth", example="1995-05-15"),
 *     @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, description="User's gender", example="female"),
 *     @OA\Property(property="linkphoto", type="string", format="url", nullable=true, description="URL to user's profile photo", example="http://example.com/jane.jpg"),
 *     @OA\Property(property="role", type="string", enum={"user", "admin", "editor"}, description="User's role in the application", example="user"),
 *     @OA\Property(property="created_at", type="string", format="date-time", description="Timestamp of user creation", readOnly=true, example="2023-01-01T12:00:00Z"),
 *     @OA\Property(property="updated_at", type="string", format="date-time", description="Timestamp of last user update", readOnly=true, example="2023-01-01T12:30:00Z"),
 *     @OA\Property(property="email_verified_at", type="string", format="date-time", nullable=true, description="Timestamp of email verification", readOnly=true, example="2023-01-01T12:05:00Z"),
 *     @OA\Property(property="user_info", ref="#/components/schemas/UserInfo", description="Additional user information", readOnly=true, nullable=true)
 * )
 */
class User extends Authenticatable implements MustVerifyEmail
{
    use HasApiTokens, HasFactory, Notifiable, HasUuids;
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'users';

    /**
     * The primary key for the model.
     *
     * @var string
     */
    protected $primaryKey = 'iduser';

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'fullname',
        'email',
        'datebirthday',
        'linkphoto',
        'gender',
        'role',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token', // Standard to hide remember_token
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime', // Standard for User models
        'datebirthday' => 'date',
        // 'password' => 'hashed', // We'll use a mutator instead for broader compatibility
    ];

    /**
     * Hash the user's password.
     *
     * @param  string  $value
     * @return void
     */
    public function setPasswordAttribute(string $value): void
    {
        $this->attributes['password'] = Hash::make($value);
    }

    /**
     * Get the columns that should receive a unique identifier.
     *
     * @return array<int, string>
     */
    public function uniqueIds(): array
    {
        return ['iduser'];
    }


    /**
     * Get the articles for the user.
     */
    public function articles(): HasMany
    {
        return $this->hasMany(Article::class, 'user_id', 'iduser');
    }

    /**
     * Get the books published/sold by the user.
     */
    public function books(): HasMany
    {
        return $this->hasMany(Book::class, 'user_id', 'iduser');
    }

    /**
     * Get the additional information associated with the user.
     */
    public function userInfo(): HasOne
    {
        return $this->hasOne(UserInfo::class, 'user_id', 'iduser');
    }



    /**
     * Send the email verification notification.
     *
     * @return void
     */
    public function sendEmailVerificationNotification()
    {
        $this->notify(new CustomVerifyEmail); // Use your custom notification
    }
}
