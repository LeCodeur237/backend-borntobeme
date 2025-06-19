<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use OpenApi\Annotations as OA;

/**
 * @OA\Schema(
 *     schema="UserInfo",
 *     type="object",
 *     title="User Info Model",
 *     description="Represents additional information for a user, like bio and preferences.",
 *     required={"id", "user_id"},
 *     @OA\Property(property="id", type="integer", format="int64", description="Primary key ID of the user info record", readOnly=true, example=1),
 *     @OA\Property(property="user_id", type="string", format="uuid", description="UUID of the user this info belongs to", example="a1b2c3d4-e5f6-7890-1234-567890abcdef"),
 *     @OA\Property(property="bio", type="string", nullable=true, description="A short biography of the user", example="Loves coding and hiking."),
 *     @OA\Property(
 *         property="preferences",
 *         type="array",
 *         @OA\Items(type="string"),
 *         nullable=true,
 *         description="A list of user interests or preferences (e.g., hobbies, topics).",
 *         example={"Book", "Read", "Sport", "Natation", "Travel"}
 *     ),
 *     @OA\Property(property="created_at", type="string", format="date-time", description="Timestamp of creation", readOnly=true),
 *     @OA\Property(property="updated_at", type="string", format="date-time", description="Timestamp of last update", readOnly=true)
 * )
 *
 * @OA\Schema(
 *     schema="UserInfoInput",
 *     type="object",
 *     title="User Info Input Data",
 *     description="Data required to create or update user information.",
 *     @OA\Property(property="bio", type="string", nullable=true, example="Passionate about web development and open source."),
 *     @OA\Property(
 *         property="preferences",
 *         type="array",
 *         @OA\Items(type="string"),
 *         nullable=true,
 *         description="A list of user interests or preferences.",
 *         example={"Photography", "Music", "Cooking"}
 *     )
 * )
 */
class UserInfo extends Model
{
    use HasFactory;

    protected $table = 'user_infos';

    protected $fillable = [
        'user_id',
        'bio',
        'preferences',
    ];

    protected $casts = [
        'preferences' => 'array', // Automatically cast JSON to/from array
    ];

    /**
     * Get the user that this information belongs to.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'iduser');
    }
}
