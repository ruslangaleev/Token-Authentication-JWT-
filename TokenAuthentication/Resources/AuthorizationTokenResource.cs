using System;

namespace TokenAuthentication.Resource
{
    /// <summary>
    /// Модель авторизованного пользователя
    /// </summary>
    public class AuthorizationTokenResource
    {
        /// <summary>
        /// Токен для доступа к ресурсам
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Токен для обновления токена доступа
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// Время существования AccessToken'a
        /// </summary>
        public TimeSpan ExpiresIn { get; set; }
    }
}
