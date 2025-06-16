<?php

namespace App\Notifications;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\URL;
use Illuminate\Auth\Notifications\VerifyEmail as VerifyEmailBase;
use Illuminate\Notifications\Messages\MailMessage;

class CustomVerifyEmail extends VerifyEmailBase
{
    /**
     * Get the mail representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return \Illuminate\Notifications\Messages\MailMessage
     */
    public function toMail($notifiable)
    {
        $verificationUrl = $this->verificationUrl($notifiable);

        if (static::$toMailCallback) {
            return call_user_func(static::$toMailCallback, $notifiable, $verificationUrl);
        }

        return (new MailMessage)
            ->subject('Verify Your Email Address - '.config('app.name')) // Customize subject
            ->greeting('Hello '.$notifiable->fullname.'!') // Custom greeting
            ->line('Thank you for registering! Please click the button below to verify your email address.') // Custom intro line
            ->action('Verify Email Address Now', $verificationUrl) // Customize button text
            ->line('If you did not create an account, no further action is required.') // Custom outro line
            ->salutation('Regards,'.PHP_EOL.config('app.name')); // Custom salutation
    }

    /**
     * Get the verification URL for the given notifiable.
     *
     * This method is inherited from VerifyEmailBase but shown here for clarity
     * on how the URL is generated if you needed to customize it further (though usually not needed).
     *
     * @param  mixed  $notifiable
     * @return string
     */
    // protected function verificationUrl($notifiable)
    // {
    //     // Logic from parent class to generate signed URL
    //     return parent::verificationUrl($notifiable);
    // }
}
