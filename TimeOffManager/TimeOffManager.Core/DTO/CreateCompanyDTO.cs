using Microsoft.AspNetCore.Http;

namespace TimeOffManager.Core.DTO
{
    public struct CreateCompanyDto
    {
        public string Name { get; set; }
        public IFormFile Logo { get; set; }
    }
}
