namespace TimeOffManager.Core.DTO.Team;

public record CreateTeamResult
{
    public string Message { get; set; }
    public bool Success { get; set; }
    public DataAccess.Models.Team? Team { get; set; }
    private CreateTeamResult(string message, bool success, DataAccess.Models.Team team)
    {
        Message = message;
        Success = success;
        Team = team;
    }

    private CreateTeamResult(string message, bool success)
    {
        Message = message;
        Success = success;
    }
    
    public static CreateTeamResult Error(string message) => new(message, false);
    public static CreateTeamResult Ok(DataAccess.Models.Team team) => new("", true, team);
}