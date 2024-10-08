using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services.Interfaces
{
    public interface ITimeOffService
    {
        public Task<TimeOff> AddTimeOffRequest(TimeOff timeOff, int approverId);
        public Task<IEnumerable<TimeOff>> GetTimeOffsByUserIdAndPeriod(int userId, int[] month, int year, bool approved);
    }
}
