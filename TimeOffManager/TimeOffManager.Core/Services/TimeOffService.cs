using Microsoft.EntityFrameworkCore;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Context;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services
{
    public class TimeOffService(DataContext dataContext) : ITimeOffService
    {
        public async Task<TimeOff> AddTimeOffRequest(TimeOff timeOff, int approverId)
        {
            timeOff.ApproverId = approverId;
            await dataContext.TimeOffs.AddAsync(timeOff);
            await dataContext.SaveChangesAsync();  
            return timeOff;
        }

        public async Task<IEnumerable<TimeOff>> GetTimeOffsByUserIdAndPeriod(int userId, int[] month, int year, bool approved)
        {
            var first = month[0];
            var last = month[month.Length - 1];

            
            var timeOffs = await dataContext.TimeOffs.Where(x => x.IsApproved == approved && x.EmployeeId == userId 
              && x.StartDate.Year == year && x.StartDate.Month >= first && x.EndDate.Month <= last).ToListAsync();

            return timeOffs;
        }
    }
}
